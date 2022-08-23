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

// Compare return values
//
//nolint:stylecheck // allow non-camel-case in constants
const (
	RHC_SAME    = blocks.CMP_SAME   // the two result handlers are the same
	RHC_MERGE   = blocks.CMP_MERGE  // the two result handlers can be merged
	RHC_DIFFER  = blocks.CMP_DIFFER // the two result handlers are different
	RHC_REPLACE = blocks.CMP_1      // the two result handlers are siblings
)

// ResultHandler for handling DHT-RESULT messages
type ResultHandler struct {
	id        int                 // task identifier
	key       *crypto.HashCode    // GET query key
	btype     enums.BlockType     // content type of the payload
	flags     uint16              // processing flags
	resFilter blocks.ResultFilter // result filter
	xQuery    []byte              // extended query
	started   util.AbsoluteTime   // Timestamp of session start
	active    bool                // is the task active?
	resp      transport.Responder // back-channel to deliver result
}

// NewResultHandler creates an instance from a DHT-GET message and a
// result filter instance.
func NewResultHandler(msg *message.DHTP2PGetMsg, rf blocks.ResultFilter, back transport.Responder) *ResultHandler {
	return &ResultHandler{
		id:        util.NextID(),
		key:       msg.Query.Clone(),
		btype:     msg.BType,
		flags:     msg.Flags,
		resFilter: rf,
		xQuery:    util.Clone(msg.XQuery),
		started:   util.AbsoluteTimeNow(),
		active:    true,
		resp:      back,
	}
}

// ID returns the result handler identifier
func (t *ResultHandler) ID() int {
	return t.id
}

// Key returns the key string
func (t *ResultHandler) Key() *crypto.HashCode {
	return t.key
}

// Receiver returns the destination peer
func (t *ResultHandler) Receiver() *util.PeerID {
	return t.resp.Receiver()
}

// Type returns the requested block type
func (t *ResultHandler) Type() enums.BlockType {
	return t.btype
}

// Flags returns the query flags
func (t *ResultHandler) Flags() uint16 {
	return t.flags
}

// Done returns true if the result handler is no longer active.
func (t *ResultHandler) Done() bool {
	return !t.active || t.started.Add(time.Hour).Expired()
}

// Compare two handlers
func (t *ResultHandler) Compare(h *ResultHandler) int {
	// check for same recipient
	tRcv := t.resp.Receiver()
	hRcv := h.resp.Receiver()
	if !hRcv.Equal(tRcv) {
		logger.Printf(logger.DBG, "[rh] recipients differ: %v -- %v", hRcv, tRcv)
		return RHC_DIFFER
	}
	// check if base attributes differ
	if !t.key.Equal(h.key) ||
		t.btype != h.btype ||
		t.flags != h.flags ||
		!bytes.Equal(t.xQuery, h.xQuery) {
		logger.Printf(logger.DBG, "[rh] base fields differ")
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
func (t *ResultHandler) Merge(a *ResultHandler) bool {
	return t.resFilter.Merge(a.resFilter)
}

// Proceed return true if the message is to be processed in derived implementations
func (t *ResultHandler) Proceed(ctx context.Context, msg *message.DHTP2PResultMsg) bool {
	blk, err := blocks.NewBlock(msg.BType, msg.Expire, msg.Block)
	if err == nil && !t.resFilter.Contains(blk) {
		t.resFilter.Add(blk)
		return true
	}
	return false
}

// Handle incoming DHT-P2P-RESULT message
func (t *ResultHandler) Handle(ctx context.Context, msg *message.DHTP2PResultMsg, pth *path.Path, sender, local *util.PeerID) bool {
	// don't send result if it is filtered out
	if !t.Proceed(ctx, msg) {
		logger.Printf(logger.DBG, "[dht-task-%d] result filtered out -- already known", t.id)
		return false
	}
	// check if we are delivering results to remote nodes
	rcv := t.resp.Receiver()
	tgt := "locally"
	if rcv != nil {
		// extend path if route is recorded
		var pp *path.Path
		if msg.Flags&enums.DHT_RO_RECORD_ROUTE != 0 {
			pp = pth.Clone()
			// yes: add path element
			pe := pp.NewElement(sender, local, rcv)
			pp.Add(pe)
		}
		// build updated PUT message
		msg = msg.Update(pp)
		tgt = rcv.Short()
	}
	// send result message back to originator (result forwarding).
	logger.Printf(logger.INFO, "[dht-task-%d] sending result back %s", t.id, tgt)
	if err := t.resp.Send(ctx, msg); err != nil && err != transport.ErrEndpMaybeSent {
		logger.Printf(logger.ERROR, "[dht-task-%d] sending result back %s failed: %s", t.id, tgt, err.Error())
		return false
	}
	return true
}

//----------------------------------------------------------------------
// Handler list for book-keeping:
// * For each query/store key there can be multiple result handlers.
//----------------------------------------------------------------------

// ResultHandlerList holds the currently active tasks
type ResultHandlerList struct {
	list *util.Map[string, []*ResultHandler] // map of handlers
}

// NewResultHandlerList creates a new task list
func NewResultHandlerList() *ResultHandlerList {
	return &ResultHandlerList{
		list: util.NewMap[string, []*ResultHandler](),
	}
}

// Add handler to list
func (t *ResultHandlerList) Add(hdlr *ResultHandler) bool {
	// get current list of handlers for key
	key := hdlr.Key().String()
	list, ok := t.list.Get(key, 0)
	modified := false
	if !ok {
		list = make([]*ResultHandler, 0)
	} else {
		// check if handler is already available
	loop:
		for i, h := range list {
			switch h.Compare(hdlr) {
			case RHC_SAME:
				// already in list; no need to add again
				logger.Println(logger.DBG, "[rhl] resultfilter compare: SAME")
				return false
			case RHC_MERGE:
				// merge the two result handlers
				oldMod := modified
				modified = h.Merge(hdlr)
				logger.Printf(logger.DBG, "[rhl] resultfilter compare: MERGE (%v -- %v)", oldMod, modified)
				break loop
			case RHC_REPLACE:
				// replace the old handler with the new one
				logger.Printf(logger.DBG, "[rhl] resultfilter compare: REPLACE #%d with #%d", list[i].id, hdlr.id)
				list[i] = hdlr
				modified = true
				break loop
			case RHC_DIFFER:
				// try next
				logger.Println(logger.DBG, "[rhl] resultfilter compare: DIFFER")
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
func (t *ResultHandlerList) Get(key string) ([]*ResultHandler, bool) {
	return t.list.Get(key, 0)
}

// Cleanup removes expired tasks from list
func (t *ResultHandlerList) Cleanup() {
	err := t.list.ProcessRange(func(key string, list []*ResultHandler, pid int) error {
		var newList []*ResultHandler
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
		logger.Printf(logger.ERROR, "[rh-list] clean-up error: %s", err.Error())
	}
}
