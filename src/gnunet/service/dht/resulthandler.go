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
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service/dht/blocks"
	"gnunet/service/dht/path"
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

	// ID returna the handler id
	ID() int

	// Done returns true if handler can be removed
	Done() bool

	// Key returns the query/store key as string
	Key() *crypto.HashCode

	// Flags returns the query flags
	Flags() uint16

	// Compare two result handlers
	Compare(ResultHandler) int

	// Merge two result handlers that are the same except for result filter
	Merge(ResultHandler) bool

	// Handle result message
	Handle(ctx context.Context, msg *message.DHTP2PResultMsg, pth *path.Path, sender, local *util.PeerID) bool
}

// Compare return values
//nolint:stylecheck // allow non-camel-case in constants
const (
	RHC_SAME    = blocks.CMP_SAME   // the two result handlers are the same
	RHC_MERGE   = blocks.CMP_MERGE  // the two result handlers can be merged
	RHC_DIFFER  = blocks.CMP_DIFFER // the two result handlers are different
	RHC_REPLACE = blocks.CMP_1      // the two result handlers are siblings
)

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
func (t *GenericResultHandler) Key() *crypto.HashCode {
	return t.key
}

// Flags returns the query flags
func (t *GenericResultHandler) Flags() uint16 {
	return t.flags
}

// Done returns true if the result handler is no longer active.
func (t *GenericResultHandler) Done() bool {
	return !t.active || t.started.Add(time.Hour).Expired()
}

// Compare two handlers
func (t *GenericResultHandler) Compare(h *GenericResultHandler) int {
	// check if base attributes differ
	if !t.key.Equals(h.key) ||
		t.btype != h.btype ||
		t.flags != h.flags ||
		!bytes.Equal(t.xQuery, h.xQuery) {
		logger.Printf(logger.DBG, "[grh] base fields differ")
		return RHC_DIFFER
	}
	// compare result filters; if they are different, replace
	// the old filter with the new one
	rc := t.resFilter.Compare(h.resFilter)
	if rc == RHC_DIFFER {
		rc = RHC_REPLACE
	}
	return rc
}

// Merge two result handlers that are the same except for result filter
func (t *GenericResultHandler) Merge(a *GenericResultHandler) bool {
	return t.resFilter.Merge(a.resFilter)
}

// Proceed return true if the message is to be processed in derived implementations
func (t *GenericResultHandler) Proceed(ctx context.Context, msg *message.DHTP2PResultMsg) bool {
	block := blocks.NewGenericBlock(msg.Block)
	if !t.resFilter.Contains(block) {
		t.resFilter.Add(block)
		return true
	}
	return false
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
func (t *ForwardResultHandler) Handle(ctx context.Context, msg *message.DHTP2PResultMsg, pth *path.Path, sender, local *util.PeerID) bool {
	// don't send result if it is filtered out
	if !t.Proceed(ctx, msg) {
		logger.Printf(logger.DBG, "[dht-task-%d] result filtered out -- already known", t.id)
		return false
	}
	// extend path if route is recorded
	pp := pth.Clone()
	if msg.Flags&enums.DHT_RO_RECORD_ROUTE != 0 {
		// yes: add path element for remote receivers
		if rcv := t.resp.Receiver(); rcv != nil {
			pe := pp.NewElement(sender, local, rcv)
			pp.Add(pe)
		}
	}

	// build updated PUT message
	msgOut := msg.Update(pp)

	// send result message back to originator (result forwarding).
	logger.Printf(logger.INFO, "[dht-task-%d] sending result back to originator", t.id)
	if err := t.resp.Send(ctx, msgOut); err != nil && err != transport.ErrEndpMaybeSent {
		logger.Printf(logger.ERROR, "[dht-task-%d] sending result back to originator failed: %s", t.id, err.Error())
		return false
	}
	return true
}

// Compare two forward result filters
func (t *ForwardResultHandler) Compare(h ResultHandler) int {
	// check for correct handler type
	ht, ok := h.(*ForwardResultHandler)
	if !ok {
		logger.Println(logger.DBG, "[frh] can't compare apples with oranges")
		return RHC_DIFFER
	}
	// check for same recipient
	if ht.resp.Receiver().Equals(t.resp.Receiver()) {
		logger.Printf(logger.DBG, "[frh] recipients differ: %s -- %s", ht.resp.Receiver(), t.resp.Receiver())
		return RHC_DIFFER
	}
	// check generic handler data
	return t.GenericResultHandler.Compare(&ht.GenericResultHandler)
}

// Merge two forward result handlers
func (t *ForwardResultHandler) Merge(h ResultHandler) bool {
	// check for correct handler type
	ht, ok := h.(*ForwardResultHandler)
	if !ok {
		return false
	}
	return t.GenericResultHandler.Merge(&ht.GenericResultHandler)
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

// ResultHandlerFcn is the function prototype for custom handlers:
type ResultHandlerFcn func(context.Context, *message.DHTP2PResultMsg, *path.Path, chan<- any) bool

// DirectResultHandler for local DHT-P2P-GET requests
type DirectResultHandler struct {
	GenericResultHandler

	hdlr ResultHandlerFcn // Hdlr is a custom message handler
	rc   chan any         // handler result channel
}

// NewDirectResultHandler create a new GET handler instance
func NewDirectResultHandler(msgIn message.Message, rf blocks.ResultFilter, hdlr ResultHandlerFcn, rc chan any) *DirectResultHandler {
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
func (t *DirectResultHandler) Handle(ctx context.Context, msg *message.DHTP2PResultMsg, pth *path.Path, sender, local *util.PeerID) bool {
	// don't send result if it is filtered out
	if !t.Proceed(ctx, msg) {
		logger.Printf(logger.DBG, "[dht-task-%d] result filtered out -- already known", t.id)
		return false
	}
	// check for correct message type and handler function
	if t.hdlr != nil {
		logger.Printf(logger.INFO, "[dht-task-%d] handling result message", t.id)
		return t.hdlr(ctx, msg, pth, t.rc)
	}
	return false
}

// Compare two direct result handlers
func (t *DirectResultHandler) Compare(h ResultHandler) int {
	// check for correct handler type
	ht, ok := h.(*DirectResultHandler)
	if !ok {
		return RHC_DIFFER
	}
	// check generic handler data
	return t.GenericResultHandler.Compare(&ht.GenericResultHandler)
}

// Merge two direct result handlers
func (t *DirectResultHandler) Merge(h ResultHandler) bool {
	// check for correct handler type
	ht, ok := h.(*DirectResultHandler)
	if !ok {
		return false
	}
	// check generic handler data
	return t.GenericResultHandler.Merge(&ht.GenericResultHandler)
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
	key := hdlr.Key().String()
	list, ok := t.list.Get(key, 0)
	modified := false
	if !ok {
		list = make([]ResultHandler, 0)
	} else {
		// check if handler is already available
	loop:
		for i, h := range list {
			switch h.Compare(hdlr) {
			case RHC_SAME:
				// already in list; no need to add again
				logger.Println(logger.DBG, "[rhl] SAME")
				return false
			case RHC_MERGE:
				// merge the two result handlers
				oldMod := modified
				modified = h.Merge(hdlr) || modified
				logger.Printf(logger.DBG, "[rhl] MERGE (%v -- %v)", oldMod, modified)
				break loop
			case RHC_REPLACE:
				// replace the old handler with the new one
				logger.Println(logger.DBG, "[rhl] REPLACE")
				list[i] = hdlr
				modified = true
				break loop
			case RHC_DIFFER:
				// try next
				logger.Println(logger.DBG, "[rhl] DIFFER")
			}
		}
	}
	if !modified {
		// append new handler to list
		list = append(list, hdlr)
	}
	t.list.Put(key, list, 0)
	return true
}

// Get handler list for given key
func (t *ResultHandlerList) Get(key string) ([]ResultHandler, bool) {
	return t.list.Get(key, 0)
}

// Cleanup removes expired tasks from list
func (t *ResultHandlerList) Cleanup() {
	err := t.list.ProcessRange(func(key string, list []ResultHandler, pid int) error {
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
			t.list.Put(key, newList, pid)
		}
		return nil
	}, false)
	if err != nil {
		logger.Printf(logger.ERROR, "[ResultHandlerList] clean-up error: %s", err.Error())
	}
}
