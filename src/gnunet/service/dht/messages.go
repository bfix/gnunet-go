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
	"context"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service/dht/blocks"
	"gnunet/service/dht/path"
	"gnunet/service/store"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/math"
)

//----------------------------------------------------------------------
// Handle DHT messages from the network
//----------------------------------------------------------------------

// HandleMessage handles a DHT request/response message. Responses are sent
// to the specified responder.
func (m *Module) HandleMessage(ctx context.Context, sender *util.PeerID, msgIn message.Message, back transport.Responder) bool {
	// assemble log label
	label := "dht"
	if v := ctx.Value("label"); v != nil {
		if s, ok := v.(string); ok && len(s) > 0 {
			label = "dht-" + s
		}
	}
	logger.Printf(logger.INFO, "[%s] message received from %s", label, sender)
	local := m.core.PeerID()

	// check for local message
	if sender.Equals(local) {
		logger.Printf(logger.WARN, "[%s] dropping local message received: %s", label, util.Dump(msgIn, "json"))
		return false
	}

	// process message
	switch msg := msgIn.(type) {

	case *message.DHTP2PGetMsg:
		//--------------------------------------------------------------
		// DHT-P2P GET
		//--------------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-GET message", label)
		query := blocks.NewGenericQuery(msg.Query, enums.BlockType(msg.BType), msg.Flags)

		var entry *store.DHTEntry
		var dist *math.Int

		//--------------------------------------------------------------
		// validate query (based on block type requested)  (9.4.3.1)
		btype := enums.BlockType(msg.BType)
		blockHdlr, ok := blocks.BlockHandlers[btype]
		if ok {
			// validate block query
			if !blockHdlr.ValidateBlockQuery(msg.Query, msg.XQuery) {
				logger.Printf(logger.WARN, "[%s] DHT-P2P-GET invalid query -- discarded", label)
				return false
			}
		} else {
			logger.Printf(logger.INFO, "[%s] no handler defined for block type %s", label, btype.String())
			blockHdlr = nil
		}
		//----------------------------------------------------------
		// check if sender is in peer filter (9.4.3.2)
		if !msg.PeerFilter.Contains(sender) {
			logger.Printf(logger.WARN, "[%s] sender not in peer filter", label)
		}
		// parse result filter ...
		var rf blocks.ResultFilter
		if msg.ResFilter != nil && len(msg.ResFilter) > 0 {
			if blockHdlr != nil {
				rf = blockHdlr.ParseResultFilter(msg.ResFilter)
			} else {
				logger.Printf(logger.WARN, "[%s] unknown result filter implementation -- skipped", label)
			}
		} else {
			// ... or create a new one
			if blockHdlr != nil {
				rf = blockHdlr.SetupResultFilter(128, util.RndUInt32())
			} else {
				logger.Printf(logger.WARN, "[%s] using default result filter", label)
				rf = blocks.NewGenericResultFilter()
			}
		}
		// clone peer filter
		pf := msg.PeerFilter.Clone()

		//----------------------------------------------------------
		// check if we need to respond (and how) (9.4.3.3)
		addr := NewQueryAddress(query.Key())
		closest := m.rtable.IsClosestPeer(nil, addr, msg.PeerFilter, 0)
		demux := int(msg.Flags)&enums.DHT_RO_DEMULTIPLEX_EVERYWHERE != 0
		approx := int(msg.Flags)&enums.DHT_RO_FIND_APPROXIMATE != 0
		// actions
		doResult := closest || (demux && approx)
		doForward := !closest || (demux && !approx)
		logger.Printf(logger.DBG, "[%s] GET message: closest=%v, demux=%v, approx=%v --> result=%v, forward=%v",
			label, closest, demux, approx, doResult, doForward)

		//------------------------------------------------------
		// query for a HELLO? (9.4.3.3a)
		if btype == enums.BLOCK_TYPE_DHT_URL_HELLO {
			// try to find result in HELLO cache
			entry, dist = m.getHelloCache(label, addr, rf)
		}
		//--------------------------------------------------------------
		// find the closest block that has that is not filtered by the result
		// filter (in case we did not find an appropriate block in cache).
		if doResult {
			// save best-match values from cache
			entryCache := entry
			distCache := dist
			dist = nil

			// if we don't have an exact match, try storage lookup
			if entryCache == nil || (distCache != nil && !distCache.Equals(math.ZERO)) {
				// get entry from local storage
				var err error
				if entry, dist, err = m.getLocalStorage(label, query, rf); err != nil {
					entry = nil
					dist = nil
				}
				// if we have a block from cache, check if it is better than the
				// block found in the DHT
				if entryCache != nil && dist != nil && distCache.Cmp(dist) < 0 {
					entry = entryCache
					dist = distCache
				}
			}
			// if we have a block, send it as response
			if entry != nil {
				logger.Printf(logger.INFO, "[%s] sending DHT result message to caller", label)
				if err := m.sendResult(ctx, query, entry.Blk, back); err != nil {
					logger.Printf(logger.ERROR, "[%s] Failed to send DHT result message: %s", label, err.Error())
				}
			}
		}
		// check if we need to forward message based on filter result
		if entry != nil && blockHdlr != nil {
			switch blockHdlr.FilterResult(entry.Blk, query.Key(), rf, msg.XQuery) {
			case blocks.RF_LAST:
				// no need for further results
			case blocks.RF_MORE:
				// possibly more results
				doForward = true
			case blocks.RF_DUPLICATE, blocks.RF_IRRELEVANT:
				// do not forward
			}
		}
		if doForward {
			// build updated GET message
			pf.Add(local)
			msgOut := msg.Update(pf, rf, msg.HopCount+1)

			// forward to number of peers
			numForward := m.rtable.ComputeOutDegree(msg.ReplLevel, msg.HopCount)
			for n := 0; n < numForward; n++ {
				if p := m.rtable.SelectClosestPeer(addr, pf, 0); p != nil {
					// forward message to peer
					logger.Printf(logger.INFO, "[%s] forward DHT get message to %s", label, p.String())
					if err := back.Send(ctx, msgOut); err != nil {
						logger.Printf(logger.ERROR, "[%s] Failed to forward DHT get message: %s", label, err.Error())
					}
					pf.Add(p.Peer)
					// create open get-forward result handler
					rh := NewForwardResultHandler(msg, rf, back)
					logger.Printf(logger.INFO, "[%s] DHT-P2P-GET task #%d (%s) started", label, rh.ID(), rh.Key())
					m.reshdlrs.Add(rh)
				} else {
					break
				}
			}
		}
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-GET message done", label)

	case *message.DHTP2PPutMsg:
		//----------------------------------------------------------
		// DHT-P2P PUT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-PUT message", label)

		// assemble query and entry
		query := blocks.NewGenericQuery(msg.Key, enums.BlockType(msg.BType), msg.Flags)
		entry := &store.DHTEntry{
			Blk:  blocks.NewGenericBlock(msg.Block),
			Path: nil,
		}

		//--------------------------------------------------------------
		// check if request is expired (9.3.2.1)
		if msg.Expiration.Expired() {
			logger.Printf(logger.WARN, "[%s] DHT-P2P-PUT message expired (%s)", label, msg.Expiration.String())
			return false
		}
		btype := enums.BlockType(msg.BType)
		blockHdlr, ok := blocks.BlockHandlers[btype]
		if ok { // (9.3.2.2)
			// reconstruct block instance
			if block, err := blockHdlr.ParseBlock(msg.Block); err == nil {

				// validate block key (9.3.2.3)
				if !blockHdlr.ValidateBlockKey(block, msg.Key) {
					logger.Printf(logger.WARN, "[%s] DHT-P2P-PUT invalid key -- discarded", label)
					return false
				}

				// validate block payload (9.3.2.4)
				if !blockHdlr.ValidateBlockStoreRequest(block) {
					logger.Printf(logger.WARN, "[%s] DHT-P2P-PUT invalid payload -- discarded", label)
					return false
				}
			}
		} else {
			logger.Printf(logger.INFO, "[%s] No validator defined for block type %s", label, btype.String())
			blockHdlr = nil
		}
		// clone peer filter
		pf := msg.PeerFilter.Clone()

		//----------------------------------------------------------
		// check if we need to respond (and how)
		addr := NewQueryAddress(msg.Key)
		closest := m.rtable.IsClosestPeer(nil, addr, msg.PeerFilter, 0)
		demux := int(msg.Flags)&enums.DHT_RO_DEMULTIPLEX_EVERYWHERE != 0
		logger.Printf(logger.DBG, "[%s] PUT message: closest=%v, demux=%v", label, closest, demux)

		//--------------------------------------------------------------
		// check if sender is in peer filter (9.3.2.5)
		if !msg.PeerFilter.Contains(sender) {
			logger.Printf(logger.WARN, "[%s] Sender not in peer filter", label)
		}
		//--------------------------------------------------------------
		// verify PUT path (9.3.2.7)
		// 'entry.Path' will be used as path in stored and forwarded messages.
		// The resulting path is always valid; it is truncated/reset on
		// signature failure.
		entry.Path = msg.Path(sender)
		entry.Path.Verify(local)

		//--------------------------------------------------------------
		// store locally if we are closest peer or demux is set (9.3.2.8)
		if closest || demux {
			// store in local storage
			if err := m.store.Put(query, entry); err != nil {
				logger.Printf(logger.ERROR, "[%s] failed to store DHT entry: %s", label, err.Error())
			}
		}

		//--------------------------------------------------------------
		// if the put is for a HELLO block, add the sender to the
		// routing table (9.3.2.9)
		if btype == enums.BLOCK_TYPE_DHT_HELLO {
			// get addresses from HELLO block
			hello, err := blocks.ParseHelloFromBytes(msg.Block)
			if err != nil {
				logger.Printf(logger.ERROR, "[%s] failed to parse HELLO block: %s", label, err.Error())
			} else {
				// check state of bucket for given address
				if m.rtable.Check(NewPeerAddress(sender)) == 0 {
					// we could add the sender to the routing table
					for _, addr := range hello.Addresses() {
						if transport.CanHandleAddress(addr) {
							// try to connect to peer (triggers EV_CONNECTED on success)
							m.core.TryConnect(sender, addr)
						}
					}
				}
			}
		}

		//--------------------------------------------------------------
		// check if we need to forward
		if !closest || demux {
			// add local node to filter
			pf.Add(local)

			// forward to computed number of peers
			numForward := m.rtable.ComputeOutDegree(msg.ReplLvl, msg.HopCount)
			for n := 0; n < numForward; n++ {
				if p := m.rtable.SelectClosestPeer(addr, pf, 0); p != nil {
					// check if route is recorded (9.3.2.6)
					var pp *path.Path
					if msg.Flags&enums.DHT_RO_RECORD_ROUTE != 0 {
						// yes: add path element
						pp = entry.Path.Clone()
						pe := pp.NewElement(sender, local, p.Peer)
						pp.Add(pe)
					}
					// build updated PUT message
					msgOut := msg.Update(pp, pf, msg.HopCount+1)

					// forward message to peer
					logger.Printf(logger.INFO, "[%s] forward DHT put message to %s", label, p.String())
					if err := back.Send(ctx, msgOut); err != nil {
						logger.Printf(logger.ERROR, "[%s] Failed to forward DHT put message: %s", label, err.Error())
					}
					// add forward node to filter
					pf.Add(p.Peer)
				} else {
					break
				}
			}
		}
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-PUT message done", label)

	case *message.DHTP2PResultMsg:
		//----------------------------------------------------------
		// DHT-P2P RESULT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-RESULT message", label)

		// check task list for handler
		key := msg.Query.String()
		logger.Printf(logger.DBG, "[%s] DHT-P2P-RESULT key = %s", label, key)
		handled := false
		if list, ok := m.reshdlrs.Get(key); ok {
			for _, rh := range list {
				logger.Printf(logger.DBG, "[%s] Task #%d for DHT-P2P-RESULT found", label, rh.ID())
				//  handle the message
				go rh.Handle(ctx, msg)
				handled = true
			}
			return true
		}
		if !handled {
			logger.Printf(logger.WARN, "[%s] DHT-P2P-RESULT not processed (no handler)", label)
		}
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-RESULT message done", label)
		return handled

	case *message.DHTP2PHelloMsg:
		//----------------------------------------------------------
		// DHT-P2P HELLO
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-HELLO message", label)

		// verify integrity of message
		if ok, err := msg.Verify(sender); !ok || err != nil {
			logger.Printf(logger.WARN, "[%s] Received invalid DHT_P2P_HELLO message", label)
			if err != nil {
				logger.Printf(logger.ERROR, "[%s] --> %s", label, err.Error())
			}
			return false
		}
		// keep peer addresses in core for transports
		aList, err := msg.Addresses()
		if err != nil {
			logger.Printf(logger.ERROR, "[%s] Failed to parse addresses from DHT_P2P_HELLO message", label)
			return false
		}
		if newPeer := m.core.Learn(ctx, sender, aList); newPeer {
			// we added a previously unknown peer: send a HELLO
			var msgOut *message.DHTP2PHelloMsg
			if msgOut, err = m.getHello(); err != nil {
				return false
			}
			logger.Printf(logger.INFO, "[%s] Sending HELLO to %s: %s", label, sender, msgOut)
			err = m.core.Send(ctx, sender, msgOut)
			// no error if the message might have been sent
			if err == transport.ErrEndpMaybeSent {
				err = nil
			}
		}

		// cache HELLO block if applicable
		k := sender.String()
		isNew := true
		if hb, ok := m.rtable.GetHello(k); ok {
			// cache entry exists: is the HELLO message more recent?
			_, isNew = hb.Expires.Diff(msg.Expires)
		}
		// we need to cache a new(er) HELLO
		if isNew {
			m.rtable.CacheHello(&blocks.HelloBlock{
				PeerID:    sender,
				Signature: msg.Signature,
				Expires:   msg.Expires,
				AddrBin:   util.Clone(msg.AddrList),
			})
		}

	//--------------------------------------------------------------
	// Legacy message types (not implemented)
	//--------------------------------------------------------------

	case *message.DHTClientPutMsg:
		//----------------------------------------------------------
		// DHT PUT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHTClientPut message", label)

	case *message.DHTClientGetMsg:
		//----------------------------------------------------------
		// DHT GET
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHTClientGet message", label)

	case *message.DHTClientGetResultsKnownMsg:
		//----------------------------------------------------------
		// DHT GET-RESULTS-KNOWN
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHTClientGetResultsKnown message", label)

	case *message.DHTClientGetStopMsg:
		//----------------------------------------------------------
		// DHT GET-STOP
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHTClientGetStop message", label)

	case *message.DHTClientResultMsg:
		//----------------------------------------------------------
		// DHT RESULT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHTClientResult message", label)

	default:
		//----------------------------------------------------------
		// UNKNOWN message type received
		//----------------------------------------------------------
		logger.Printf(logger.ERROR, "[%s] Unhandled message of type (%d)\n", label, msgIn.Header().MsgType)
		return false
	}
	return true
}

// send a result back to caller
func (m *Module) sendResult(ctx context.Context, query blocks.Query, blk blocks.Block, back transport.Responder) error {
	// assemble result message
	out := message.NewDHTP2PResultMsg()
	out.BType = uint32(query.Type())
	out.Expires = blk.Expire()
	out.Query = query.Key()
	out.Block = blk.Bytes()
	out.MsgSize += uint16(len(out.Block))
	// send message
	return back.Send(ctx, out)
}
