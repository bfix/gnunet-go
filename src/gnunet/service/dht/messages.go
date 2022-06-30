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
		if s := v.(string); len(s) > 0 {
			label = "dht-" + s
		}
	}
	logger.Printf(logger.INFO, "[%s] message received from %s", label, sender)

	// process message
	switch msg := msgIn.(type) {

	case *message.DHTP2PGetMsg:
		//--------------------------------------------------------------
		// DHT-P2P GET
		//--------------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-GET message", label)
		query := blocks.NewGenericQuery(msg.Query.Bits, enums.BlockType(msg.BType), msg.Flags)

		var block blocks.Block
		var dist *math.Int
		var err error

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
			logger.Printf(logger.INFO, "[%s] No validator defined for block type %s", label, btype.String())
		}
		//----------------------------------------------------------
		// check if sender is in peer filter (9.4.3.2)
		if !msg.PeerFilter.Contains(sender) {
			logger.Printf(logger.WARN, "[dht] Sender not in peer filter")
		}
		// parse result filter
		var rf blocks.ResultFilter = new(blocks.PassResultFilter)
		if msg.ResFilter != nil && len(msg.ResFilter) > 0 {
			rf = blocks.NewHelloResultFilterFromBytes(msg.ResFilter)
		}
		// clone peer filter
		pf := msg.PeerFilter.Clone()

		//----------------------------------------------------------
		// check if we need to respond (and how) (9.4.3.3)
		addr := NewQueryAddress(msg.Query)
		closest := m.rtable.IsClosestPeer(nil, addr, msg.PeerFilter)
		demux := int(msg.Flags)&enums.DHT_RO_DEMULTIPLEX_EVERYWHERE != 0
		approx := int(msg.Flags)&enums.DHT_RO_FIND_APPROXIMATE != 0
		// actions
		do_result := closest || (demux && approx)
		do_forward := !closest || (demux && !approx)
		logger.Printf(logger.DBG, "[dht] GET message: closest=%v, demux=%v, approx=%v --> result=%v, forward=%v",
			closest, demux, approx, do_result, do_forward)

		//------------------------------------------------------
		// query for a HELLO? (9.4.3.3a)
		if msg.BType == uint32(enums.BLOCK_TYPE_DHT_URL_HELLO) {
			logger.Println(logger.DBG, "[dht] GET message for HELLO: check cache")
			// find best cached HELLO
			block, dist = m.rtable.BestHello(addr, rf)
		}
		//--------------------------------------------------------------
		// find the closest block that has that is not filtered/ by the result
		// filter (in case we did not find an appropriate block in cache).
		if do_result {
			// save best-match values from cache
			block_cache := block
			dist_cache := dist

			// query DHT store for exact match  (9.4.3.3c)
			if block, err = m.Get(ctx, query); err != nil {
				logger.Printf(logger.ERROR, "[%s] Failed to get DHT block from storage: %s", label, err.Error())
				return true
			}
			// if block is filtered, skip it
			if rf.Contains(block) {
				logger.Println(logger.DBG, "[dht] GET message for HELLO: matching DHT block is filtered")
				block = nil
			}
			// if we have no exact match, find approximate block if requested
			if block == nil || approx {
				// no exact match: find approximate (9.4.3.3b)
				match := func(b blocks.Block) bool {
					return rf.Contains(b)
				}
				block, dist, err = m.GetApprox(ctx, query, match)
				if err != nil {
					logger.Printf(logger.ERROR, "[%s] Failed to get (approx.) DHT block from storage: %s", label, err.Error())
					return true
				}
			}
			// if we have a block from cache, check if it is better than the
			// block found in the DHT
			if block_cache != nil && dist_cache.Cmp(dist) < 0 {
				block = block_cache
				dist = dist_cache
			}
			// if we have a block, send it as response
			if block != nil {
				logger.Println(logger.INFO, "[dht] sending DHT result message to caller")
				if err := m.sendResult(ctx, query, block, back); err != nil {
					logger.Println(logger.ERROR, "[dht] Failed to send DHT result message: "+err.Error())
				}
			}
		}
		// check if we need to forward message based on filter result
		if block != nil && blockHdlr != nil {
			switch blockHdlr.FilterResult(block, query.Key(), rf, msg.XQuery) {
			case blocks.RF_LAST:
				// no need for further results
			case blocks.RF_MORE:
				// possibly more results
				do_forward = true
			case blocks.RF_DUPLICATE, blocks.RF_IRRELEVANT:
				// do not forward
			}
		}
		if do_forward {
			// build updated GET message
			pf.Add(m.core.PeerID())
			msgOut := msg.Update(pf, rf, msg.HopCount+1)

			// forward to number of peers
			numForward := m.rtable.ComputeOutDegree(msg.ReplLevel, msg.HopCount)
			key := NewQueryAddress(query.Key())
			for n := 0; n < numForward; n++ {
				if p := m.rtable.SelectClosestPeer(key, pf); p != nil {
					// forward message to peer
					logger.Printf(logger.INFO, "[dht] forward DHT get message to %s", p.String())
					if err := back.Send(ctx, msgOut); err != nil {
						logger.Println(logger.ERROR, "[dht] Failed to forward DHT get message: "+err.Error())
					}
					pf.Add(p.Peer)
					// create open get-forward-task
					task := NewGetForwardTask(query.Key(), p.Peer, sender, back)
					logger.Printf(logger.INFO, "[%s] DHT-P2P-GET task #%d started", label, task.ID())
					m.tasks.Add(task)
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

	case *message.DHTP2PResultMsg:
		//----------------------------------------------------------
		// DHT-P2P RESULT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-RESULT message", label)

		// check task list for handler (get and getforward tasks)
		key := GetTaskKey(msg.Query, sender)
		task, ok := m.tasks.Get(key)
		if !ok {
			key = GetForwardTaskKey(msg.Query, sender)
			task, ok = m.tasks.Get(key)
		}
		if ok {
			logger.Printf(logger.DBG, "[%s] Task #%d for DHT-P2P-RESULT found", label, task.ID())
			// let the task handle the message
			go task.Handle(ctx, msg)
			return true
		}
		logger.Printf(logger.WARN, "[%s] DHT-P2P-RESULT not processed!", label)
		return false

	case *message.DHTP2PHelloMsg:
		//----------------------------------------------------------
		// DHT-P2P HELLO
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-HELLO message", label)

		// verify integrity of message
		if ok, err := msg.Verify(sender); !ok || err != nil {
			logger.Println(logger.WARN, "[dht] Received invalid DHT_P2P_HELLO message")
			if err != nil {
				logger.Println(logger.ERROR, "[dht] --> "+err.Error())
			}
			return false
		}
		// keep peer addresses in core for transport
		aList, err := msg.Addresses()
		if err != nil {
			logger.Println(logger.ERROR, "[dht] Failed to parse addresses from DHT_P2P_HELLO message")
			return false
		}
		if newPeer := m.core.Learn(ctx, sender, aList); newPeer {
			// we added a previously unknown peer: send a HELLO
			var msgOut *message.DHTP2PHelloMsg
			if msgOut, err = m.getHello(); err != nil {
				return false
			}
			logger.Printf(logger.INFO, "[dht] Sending HELLO to %s: %s", sender, msgOut)
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
	out.Block = blk.Data()
	out.MsgSize += uint16(len(out.Block))
	// send message
	return back.Send(ctx, out)
}
