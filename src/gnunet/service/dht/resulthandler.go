// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2022 Bernd Fix  >Y<
//
// gnunet-go is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// gnunet-go is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL3.0-or-later

package dht

import (
	"bytes"
	"context"
	"gnunet/crypto"
	"gnunet/message"
	"gnunet/service/dht/blocks"
	"gnunet/transport"
	"gnunet/util"
	"time"

	"github.com/bfix/gospel/logger"
)

//======================================================================
// DHT GET requests send to neighbours result in DHT RESULT messages
// being returned that need to be handled. The sequence of incoming
// results is undetermined and usually not terminated (that is, there
// is no mechanism to determine the end of results).
// ResultHandlers handle DHT RESULT messages. The appropriate handler
// is selected by the DHT query/store key associated with a GET/RESULT
// message; there can be multiple handlers for the same key (serving
// different GET requests and/or differnent originators).
//======================================================================

// ResultHandler interface
type ResultHandler interface {
	ID() int
	Done() bool
	Key() string
	Equal(ResultHandler) bool
	Handle(ctx context.Context, msg *message.DHTP2PResultMsg) bool
}

//----------------------------------------------------------------------

// Generic (shared) result handler data structure
type GenericResultHandler struct {
	id        int                 // task identifier
	key       *crypto.HashCode    // GET query key
	btype     uint32              // content type of the payload
	flags     uint16              // processing flags
	resFilter blocks.ResultFilter // result filter
	xQuery    []byte              // extended query
	started   util.AbsoluteTime   // Timestamp of session start
	active    bool                // is the task active?
}

// NewGenericResultHandler creates an instance from a DHT-GET message and a
// result filter instance.
func NewGenericResultHandler(msg *message.DHTP2PGetMsg, rf blocks.ResultFilter) *GenericResultHandler {
	return &GenericResultHandler{
		id:        util.NextID(),
		key:       msg.Query.Clone(),
		btype:     msg.BType,
		flags:     msg.Flags,
		resFilter: rf,
		xQuery:    util.Clone(msg.XQuery),
		started:   util.AbsoluteTimeNow(),
		active:    true,
	}
}

// ID returns the result handler identifier
func (t *GenericResultHandler) ID() int {
	return t.id
}

// Key returns the key string
func (t *GenericResultHandler) Key() string {
	return t.key.String()
}

// Done returns true if the result handler is no longer active.
func (t *GenericResultHandler) Done() bool {
	return !t.active || t.started.Add(time.Hour).Expired()
}

// Equal returns true if the two handlers handle the same result
// for a recipient.
func (t *GenericResultHandler) Equal(h *GenericResultHandler) bool {
	if t.btype != h.btype || t.flags != h.flags {
		return false
	}
	if !t.resFilter.Equal(h.resFilter) {
		return false
	}
	return bytes.Equal(t.xQuery, h.xQuery)
}

//----------------------------------------------------------------------
// Result handler for forwarded GET requests
//----------------------------------------------------------------------

// ForwardResultHandler data structure
type ForwardResultHandler struct {
	GenericResultHandler

	resp transport.Responder // responder for communicating back to originator
}

// NewForwardResultHandler derived from DHT-GET message
func NewForwardResultHandler(msgIn message.Message, rf blocks.ResultFilter, back transport.Responder) *ForwardResultHandler {
	// check for correct message type and handler function
	msg, ok := msgIn.(*message.DHTP2PGetMsg)
	if ok {
		return &ForwardResultHandler{
			GenericResultHandler: *NewGenericResultHandler(msg, rf),
			resp:                 back,
		}
	}
	return nil
}

// Handle incoming DHT-P2P-RESULT message
func (t *ForwardResultHandler) Handle(ctx context.Context, msg *message.DHTP2PResultMsg) bool {
	// send result message back to originator (result forwarding).
	logger.Printf(logger.INFO, "[dht-task-%d] sending result back to originator", t.ID)
	if err := t.resp.Send(ctx, msg); err != nil && err != transport.ErrEndpMaybeSent {
		logger.Printf(logger.ERROR, "[dht-task-%d] sending result back to originator failed: %s", t.ID, err.Error())
		return false
	}
	return true
}

// Equal returns true if the two handlers handle the same result
// for a recipient.
func (t *ForwardResultHandler) Equal(h ResultHandler) bool {
	// check for correct handler type
	ht, ok := h.(*ForwardResultHandler)
	if !ok {
		return false
	}
	// check generic handler data
	if !ht.GenericResultHandler.Equal(&ht.GenericResultHandler) {
		return false
	}
	// check for same recipient
	return ht.resp.Receiver() == t.resp.Receiver()
}

//----------------------------------------------------------------------
// Result handler for locally-initiated GET requests:
//
// Before sending the GET request a handler is added for the request:
//
//    rc := make(chan any)
//    myRH := NewDirectResultHandler(msg, rf, MyCustomHandler, rc)
//    m.reshdlrs.Add(myRH)
//
// If a matching response is received, the custom handler is executed
// in a separate go-routine. A custom handler returns a result (or error) on
// a back channel and should be context-sensitive (termination).
//
// If an asynchronous behaviour is required, use 'ret := <-rc' to wait for
// completion; synchronous execution does not require 'rc' (which can be set
// to nil).
//----------------------------------------------------------------------

// CustomResultHandler is the function prototype for custom handlers:
type CustomResultHandler func(context.Context, *message.DHTP2PResultMsg, chan<- any) bool

// DirectResultHandler for local DHT-P2P-GET requests
type DirectResultHandler struct {
	GenericResultHandler

	hdlr CustomResultHandler // Hdlr is a custom message handler
	rc   chan any            // handler result channel
}

// NewDirectResultHandler create a new GET handler instance
func NewDirectResultHandler(msgIn message.Message, rf blocks.ResultFilter, hdlr CustomResultHandler, rc chan any) *DirectResultHandler {
	// check for correct message type and handler function
	msg, ok := msgIn.(*message.DHTP2PGetMsg)
	if ok {
		return &DirectResultHandler{
			GenericResultHandler: *NewGenericResultHandler(msg, rf),
			hdlr:                 hdlr,
			rc:                   rc,
		}
	}
	return nil
}

// Handle incoming DHT-P2P-RESULT message
func (t *DirectResultHandler) Handle(ctx context.Context, msg *message.DHTP2PResultMsg) bool {
	// check for correct message type and handler function
	if t.hdlr != nil {
		logger.Printf(logger.INFO, "[dht-task-%d] handling result message", t.id)
		return t.hdlr(ctx, msg, t.rc)
	}
	return false
}

// Equal returns true if the two handlers handle the same result
// for a recipient.
func (t *DirectResultHandler) Equal(h ResultHandler) bool {
	// check for correct handler type
	ht, ok := h.(*DirectResultHandler)
	if !ok {
		return false
	}
	// check generic handler data
	return ht.GenericResultHandler.Equal(&ht.GenericResultHandler)
}

//----------------------------------------------------------------------
// Handler list for book-keeping:
// * For each query/store key there can be multiple result handlers.
//----------------------------------------------------------------------

// ResultHandlerList holds the currently active tasks
type ResultHandlerList struct {
	list *util.Map[string, []ResultHandler] // map of handlers
}

// NewResultHandlerList creates a new task list
func NewResultHandlerList() *ResultHandlerList {
	return &ResultHandlerList{
		list: util.NewMap[string, []ResultHandler](),
	}
}

// Add handler to list
func (t *ResultHandlerList) Add(hdlr ResultHandler) bool {
	// get current list of handlers for key
	key := hdlr.Key()
	list, ok := t.list.Get(key)
	if !ok {
		list = make([]ResultHandler, 0)
	} else {
		// check if handler is already available
		for _, h := range list {
			if h.Equal(hdlr) {
				return false
			}
		}
	}
	// append handler to list
	list = append(list, hdlr)
	t.list.Put(key, list)
	return true
}

// Get handler list for given key
func (t *ResultHandlerList) Get(key string) ([]ResultHandler, bool) {
	return t.list.Get(key)
}

// Cleanup removes expired tasks from list
func (t *ResultHandlerList) Cleanup() {
	t.list.ProcessRange(func(key string, list []ResultHandler) error {
		var newList []ResultHandler
		changed := false
		for _, rh := range list {
			if !rh.Done() {
				newList = append(newList, rh)
			} else {
				changed = true
			}
		}
		if changed {
			t.list.Put(key, newList)
		}
		return nil
	}, false)
}
