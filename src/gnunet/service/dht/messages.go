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
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service/dht/blocks"
	"gnunet/service/dht/path"
	"gnunet/service/store"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// Handle DHT messages from the network
//----------------------------------------------------------------------

// HandleMessage handles a DHT request/response message. Responses are sent
// to the specified responder.
//nolint:gocyclo // life sometimes is complex...
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

	// process message
	switch msg := msgIn.(type) {

	//==================================================================
	// DHT-P2P-GET
	//==================================================================
	case *message.DHTP2PGetMsg:
		//--------------------------------------------------------------
		// DHT-P2P GET
		//--------------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-GET message", label)

		// assemble query and initialize (cache) results
		query := blocks.NewGenericQuery(msg.Query, enums.BlockType(msg.BType), msg.Flags)
		var results []*store.DHTResult

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

		// enforced actions
		doResult, doForward := getActions(closest, demux, approx)
		logger.Printf(logger.DBG, "[%s] GET message: closest=%v, demux=%v, approx=%v --> result=%v, forward=%v",
			label, closest, demux, approx, doResult, doForward)

		//------------------------------------------------------
		// query for a HELLO? (9.4.3.3a)
		if btype == enums.BLOCK_TYPE_DHT_URL_HELLO {
			// try to find results in HELLO cache
			results = m.lookupHelloCache(label, addr, rf, approx)
		}

		//--------------------------------------------------------------
		// query flags demand a result
		if doResult {
			// if we don't have a result from cache or are in approx mode,
			// try storage lookup
			if len(results) == 0 || approx {
				// get results from local storage
				lclResults, err := m.getLocalStorage(label, query, rf)
				if err == nil {
					// append local results
					results = append(results, lclResults...)
				}
			}
			// if we have results, send them as response
			for _, result := range results {
				var pth *path.Path
				// check if record the route
				if msg.Flags&enums.DHT_RO_RECORD_ROUTE != 0 && result.Entry.Path != nil {
					// update get path
					pth = result.Entry.Path.Clone()
					pth.SplitPos = pth.NumList
					pe := pth.NewElement(pth.LastHop, local, back.Receiver())
					pth.Add(pe)
				}

				logger.Printf(logger.INFO, "[%s] sending DHT result message to caller", label)
				if err := m.sendResult(ctx, query, result.Entry.Blk, pth, back); err != nil {
					logger.Printf(logger.ERROR, "[%s] Failed to send DHT result message: %s", label, err.Error())
				}
			}
		}
		//--------------------------------------------------------------
		// query flags demand a result
		if doForward {
			// build updated GET message
			pf.Add(local)
			msgOut := msg.Update(pf, rf, msg.HopCount+1)

			// forward to number of peers
			numForward := m.rtable.ComputeOutDegree(msg.ReplLevel, msg.HopCount)
			for n := 0; n < numForward; n++ {
				if p := m.rtable.SelectClosestPeer(addr, pf, 0); p != nil {
					// forward message to peer
					logger.Printf(logger.INFO, "[%s] forward DHT get message to %s", label, util.Shorten(p.Peer.String(), 20))
					if err := m.core.Send(ctx, p.Peer, msgOut); err != nil {
						logger.Printf(logger.ERROR, "[%s] Failed to forward DHT get message: %s", label, err.Error())
					}
					pf.Add(p.Peer)
					// create open get-forward result handler
					rh := NewResultHandler(msg, rf, back)
					logger.Printf(logger.INFO, "[%s] DHT-P2P-GET task #%d (%s) started",
						label, rh.ID(), util.Shorten(rh.Key().String(), 20))
					m.reshdlrs.Add(rh)
				} else {
					break
				}
			}
		}
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-GET message done", label)

	//==================================================================
	// DHT-P2P-PUT
	//==================================================================
	case *message.DHTP2PPutMsg:
		//----------------------------------------------------------
		// DHT-P2P PUT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-PUT message", label)

		// assemble query and entry
		btype := enums.BlockType(msg.BType)
		query := blocks.NewGenericQuery(msg.Key, btype, msg.Flags)
		blk, err := blocks.NewBlock(btype, msg.Expire, msg.Block)
		if err != nil {
			logger.Printf(logger.ERROR, "[%s] DHT-P2P-PUT message block problem: %s", label, err.Error())
			return false
		}
		entry := &store.DHTEntry{
			Blk:  blk,
			Path: nil,
		}

		//--------------------------------------------------------------
		// check if request is expired (9.3.2.1)
		if msg.Expire.Expired() {
			logger.Printf(logger.WARN, "[%s] DHT-P2P-PUT message expired (%s)", label, msg.Expire.String())
			return false
		}
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
		doStore, doForward := putActions(closest, demux)
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
		if doStore {
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
			hello, err := blocks.ParseHelloBlockFromBytes(msg.Block)
			if err != nil {
				logger.Printf(logger.ERROR, "[%s] failed to parse HELLO block: %s", label, err.Error())
			} else {
				// check state of bucket for given address
				if m.rtable.Check(NewPeerAddress(hello.PeerID)) == 0 {
					// we could add the sender to the routing table
					for _, addr := range hello.Addresses() {
						if transport.CanHandleAddress(addr) {
							// try to connect to peer (triggers EV_CONNECTED on success)
							if err := m.core.TryConnect(sender, addr); err != nil {
								logger.Printf(logger.ERROR, "[%s] try-connection to %s failed: %s", label, addr.URI(), err.Error())
							}
						}
					}
				}
			}
		}
		//--------------------------------------------------------------
		// check if we need to forward
		if doForward {
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
					logger.Printf(logger.INFO, "[%s] forward DHT put message to %s", label, p.Peer.String())
					if err := m.core.Send(ctx, p.Peer, msgOut); err != nil {
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

	//==================================================================
	// DHT-P2P-RESULT
	//==================================================================
	case *message.DHTP2PResultMsg:
		//----------------------------------------------------------
		// DHT-P2P RESULT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-RESULT message for type %s",
			label, enums.BlockType(msg.BType).String())

		//--------------------------------------------------------------
		// check if request is expired (9.5.2.1)
		if msg.Expire.Expired() {
			logger.Printf(logger.WARN, "[%s] DHT-P2P-RESULT message expired (%s)",
				label, msg.Expire.String())
			return false
		}
		//--------------------------------------------------------------
		btype := enums.BlockType(msg.BType)
		var blkKey *crypto.HashCode
		blockHdlr, ok := blocks.BlockHandlers[btype]
		if ok {
			// reconstruct block instance
			if block, err := blockHdlr.ParseBlock(msg.Block); err == nil {
				// validate block (9.5.2.2)
				if !blockHdlr.ValidateBlockStoreRequest(block) {
					logger.Printf(logger.WARN, "[%s] DHT-P2P-RESULT invalid block -- discarded", label)
					return false
				}
				// Compute block key (9.5.2.4)
				blkKey = blockHdlr.DeriveBlockKey(block)
			}
		} else {
			logger.Printf(logger.INFO, "[%s] No validator defined for block type %s", label, btype.String())
			blockHdlr = nil
		}
		//--------------------------------------------------------------
		// verify path (9.5.2.3)
		var pth *path.Path
		if msg.GetPathL+msg.PutPathL > 0 {
			pth = msg.Path(sender)
			pth.Verify(local)
		}
		//--------------------------------------------------------------
		// if the put is for a HELLO block, add the originator to the
		// routing table (9.5.2.5)
		if btype == enums.BLOCK_TYPE_DHT_HELLO {
			// get addresses from HELLO block
			hello, err := blocks.ParseHelloBlockFromBytes(msg.Block)
			if err != nil {
				logger.Printf(logger.ERROR, "[%s] failed to parse HELLO block: %s", label, err.Error())
			} else {
				// check state of bucket for given address
				if m.rtable.Check(NewPeerAddress(hello.PeerID)) == 0 {
					// we could add the originator to the routing table
					for _, addr := range hello.Addresses() {
						if transport.CanHandleAddress(addr) {
							// try to connect to peer (triggers EV_CONNECTED on success)
							if err := m.core.TryConnect(sender, addr); err != nil {
								logger.Printf(logger.ERROR, "[%s] try-connection to %s failed: %s", label, addr.URI(), err.Error())
							}
						}
					}
				}
			}
		}
		// message forwarding to responder
		key := msg.Query.String()
		logger.Printf(logger.DBG, "[%s] DHT-P2P-RESULT key = %s", label, key)
		handled := false
		if list, ok := m.reshdlrs.Get(key); ok {
			for _, rh := range list {
				logger.Printf(logger.DBG, "[%s] Task #%d for DHT-P2P-RESULT found", label, rh.ID())

				//--------------------------------------------------------------
				// check task list for handler (9.5.2.6)
				if rh.Flags()&enums.DHT_RO_FIND_APPROXIMATE == 0 && blkKey != nil && !blkKey.Equal(rh.Key()) {
					// (9.5.2.6.a) derived key mismatch
					logger.Printf(logger.ERROR, "[%s] derived block key / query key mismatch:", label)
					logger.Printf(logger.ERROR, "[%s]   --> %s != %s", label, blkKey.String(), rh.Key().String())
					return false
				}
				// (9.5.2.6.b+c) check block against query
				/*
					if blockHdlr != nil {
						blockHdlr.FilterBlockResult(block, rh.Key())
					}
				*/

				//--------------------------------------------------------------
				//  handle the message (forwarding)
				go rh.Handle(ctx, msg, pth, sender, local)
				handled = true
			}
		}
		if !handled {
			logger.Printf(logger.WARN, "[%s] DHT-P2P-RESULT not processed (no handler)", label)
		}
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-RESULT message done", label)
		return handled

	//==================================================================
	// DHT-P2P-HELLO
	//==================================================================
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
			logger.Printf(logger.INFO, "[%s] Sending own HELLO to %s", label, sender)
			err = m.core.Send(ctx, sender, msgOut)
			// no error if the message might have been sent
			if err != nil && err != transport.ErrEndpMaybeSent {
				logger.Printf(logger.ERROR, "[%s] -> failed to send HELLO message: %s", label, err.Error())
			}
		}

		// cache HELLO block if applicable
		k := sender.String()
		isNew := true
		if hb, ok := m.rtable.GetHello(k); ok {
			// cache entry exists: is the HELLO message more recent?
			_, isNew = hb.Expire_.Diff(msg.Expire)
		}
		// we need to cache a new(er) HELLO
		if isNew {
			m.rtable.CacheHello(&blocks.HelloBlock{
				PeerID:    sender,
				Signature: msg.Signature,
				Expire_:   msg.Expire,
				AddrBin:   util.Clone(msg.AddrList),
			})
		}

	//==================================================================
	// Legacy message types (not implemented)
	//==================================================================

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

//----------------------------------------------------------------------
// Helpers
//----------------------------------------------------------------------

// send a result back to caller
func (m *Module) sendResult(ctx context.Context, query blocks.Query, blk blocks.Block, pth *path.Path, back transport.Responder) error {
	// assemble result message
	out := message.NewDHTP2PResultMsg()
	out.BType = uint32(query.Type())
	out.Flags = uint32(query.Flags())
	out.Expire = blk.Expire()
	out.Query = query.Key()
	out.Block = blk.Bytes()
	out.MsgSize += uint16(len(out.Block))
	out.SetPath(pth)

	// send message
	return back.Send(ctx, out)
}

// get enforced action for GET message
func getActions(closest, demux, approx bool) (doResult, doForward bool) {
	return closest || (demux && approx), !closest || (demux && !approx)
}

// get enforced action for PUT message
func putActions(closest, demux bool) (doStore, doForward bool) {
	return closest || demux, !closest || demux
}
