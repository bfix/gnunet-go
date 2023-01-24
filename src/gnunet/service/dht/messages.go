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
	"gnunet/core"
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

// MaxSortResults is the max. number of sorted results
const MaxSortResults = 10

// HandleMessage handles a DHT request/response message. Responses are sent
// to the specified responder.
//
//nolint:gocyclo // life sometimes is complex...
func (m *Module) HandleMessage(ctx context.Context, sender *util.PeerID, msgIn message.Message, back transport.Responder) bool {
	// assemble log label
	label := "dht"
	if v := ctx.Value(core.CtxKey("label")); v != nil {
		if s, ok := v.(string); ok && len(s) > 0 {
			label = s
		}
	}
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
		logger.Printf(logger.INFO, "[%s] DHT-P2P-GET from %s (type %s, flags=%s)",
			label, sender.Short(), msg.BType, message.DHTFlags(msg.Flags))

		// assemble query and initialize (cache) results
		query := blocks.NewGenericQuery(msg.Query, msg.BType, msg.Flags)
		var results []*store.DHTResult

		//--------------------------------------------------------------
		// validate query (based on block type requested)  (9.4.3.1)
		btype := msg.BType
		blockHdlr, ok := blocks.BlockHandlers[btype]
		if ok {
			// validate block query
			if !blockHdlr.ValidateBlockQuery(msg.Query, msg.XQuery) {
				logger.Printf(logger.WARN, "[%s] invalid query -- message discarded", label)
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
				logger.Printf(logger.WARN, "[%s] unknown result filter implementation -- message discarded", label)
				return false
			}
		} else {
			// ... or create a new one
			mut := util.RndUInt32()
			if blockHdlr != nil {
				rf = blockHdlr.SetupResultFilter(128, mut)
			} else {
				logger.Printf(logger.WARN, "[%s] using default result filter", label)
				rf = blocks.NewGenericResultFilter(128, mut)
			}
		}
		// clone peer filter
		pf := msg.PeerFilter.Clone()

		//----------------------------------------------------------
		// check if we need to respond (and how) (9.4.3.3)
		addr := NewQueryAddress(query.Key())
		demux := int(msg.Flags)&enums.DHT_RO_DEMULTIPLEX_EVERYWHERE != 0
		approx := int(msg.Flags)&enums.DHT_RO_FIND_APPROXIMATE != 0
		closest := false
		// only check for closest node if we are not looking for our own HELLO
		if msg.Flags&enums.DHT_RO_DISCOVERY == 0 {
			closest = m.rtable.IsClosestPeer(nil, addr, msg.PeerFilter, 0)
		} else {
			// remove discovery flag
			msg.Flags &^= enums.DHT_RO_DISCOVERY
		}
		// enforced actions
		doResult, doForward := getActions(closest, demux, approx)
		logger.Printf(logger.DBG, "[%s] Actions: closest=%v, demux=%v, approx=%v --> result=%v, forward=%v",
			label, closest, demux, approx, doResult, doForward)

		//------------------------------------------------------
		// query for a HELLO? (9.4.3.3a)
		if btype == enums.BLOCK_TYPE_DHT_URL_HELLO {
			// try to find results in HELLO cache
			results = m.lookupHelloCache(label, addr, rf, approx)
			// DEBUG:
			for i, res := range results {
				logger.Printf(logger.DBG, "[%s] cache #%d = %s", label, i, res)
			}
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
					// DEBUG:
					for i, res := range lclResults {
						logger.Printf(logger.DBG, "[%s] local #%d = %s", label, i, res)
					}
					// create total result list
					if len(results) == 0 {
						results = lclResults
					} else if len(results)+len(lclResults) <= MaxSortResults {
						// handle few results directly
						results = append(results, lclResults...)
					} else {
						// compile a new sorted list from results.
						list := store.NewSortedDHTResults(MaxSortResults)
						for pos, res := range results {
							list.Add(res, pos)
						}
						for _, res := range lclResults {
							if pos := list.Accepts(res.Dist); pos != -1 {
								list.Add(res, pos)
							}
						}
						results = list.GetResults()
					}
				}
			}
			// if we have results, send them as response on the back channel
			rcv := "local caller"
			if back.Receiver() != nil {
				rcv = back.Receiver().Short()
			}
			for _, result := range results {
				var pth *path.Path
				// check if record the route
				if msg.Flags&enums.DHT_RO_RECORD_ROUTE != 0 && result.Entry.Path != nil {
					// update get path
					pth = result.Entry.Path.Clone()
					pth.SplitPos = pth.NumList
					pe := pth.NewElement(pth.LastHop, local, back.Receiver())
					if err := m.core.Sign(pe); err != nil {
						logger.Printf(logger.ERROR, "[%s] failed to sign path element: %s", label, err.Error())
					} else {
						pth.Add(pe)
					}
				}

				logger.Printf(logger.INFO, "[%s] sending result message to %s", label, rcv)
				if err := m.sendResult(ctx, query, result.Entry.Blk, pth, back); err != nil {
					logger.Printf(logger.ERROR, "[%s] Failed to send result message: %s", label, err.Error())
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
				if p := m.rtable.SelectPeer(addr, msg.HopCount, pf, 0); p != nil {
					// forward message to peer
					logger.Printf(logger.INFO, "[%s] forward GET message to %s", label, p.Peer.Short())
					if err := m.core.Send(ctx, p.Peer, msgOut); err != nil {
						logger.Printf(logger.ERROR, "[%s] Failed to forward GET message: %s", label, err.Error())
					}
					pf.Add(p.Peer)
					// create open get-forward result handler
					rh := NewResultHandler(msg, rf, back, m.core)
					logger.Printf(logger.INFO, "[%s] result handler task #%d (key %s) started",
						label, rh.ID(), rh.Key().Short())
					m.reshdlrs.Add(rh)
				} else {
					break
				}
			}
		}
		logger.Printf(logger.INFO, "[%s] DHT-P2P-GET done", label)

	//==================================================================
	// DHT-P2P-PUT
	//==================================================================
	case *message.DHTP2PPutMsg:
		//----------------------------------------------------------
		// DHT-P2P PUT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] DHT-P2P-PUT from %s (type %s, flags=%s)",
			label, sender.Short(), msg.BType, message.DHTFlags(msg.Flags))

		// assemble query and entry
		query := blocks.NewGenericQuery(msg.Key, msg.BType, msg.Flags)
		blk, err := blocks.NewBlock(msg.BType, msg.Expire, msg.Block)
		if err != nil {
			logger.Printf(logger.ERROR, "[%s] message block problem: %s", label, err.Error())
			return false
		}
		entry := &store.DHTEntry{
			Blk:  blk,
			Path: nil,
		}

		//--------------------------------------------------------------
		// check if request is expired (9.3.2.1)
		if msg.Expire.Expired() {
			logger.Printf(logger.WARN, "[%s] PUT message expired (%s) -- ignored", label, msg.Expire)
			return false
		}
		blockHdlr, ok := blocks.BlockHandlers[msg.BType]
		if ok { // (9.3.2.2)
			// reconstruct block instance
			if block, err := blockHdlr.ParseBlock(msg.Block); err == nil {

				// validate block key (9.3.2.3)
				if !blockHdlr.ValidateBlockKey(block, msg.Key) {
					logger.Printf(logger.WARN, "[%s] PUT invalid key -- discarded", label)
					return false
				}

				// validate block payload (9.3.2.4)
				if !blockHdlr.ValidateBlockStoreRequest(block) {
					logger.Printf(logger.WARN, "[%s] PUT invalid payload -- discarded", label)
					return false
				}
			}
		} else {
			logger.Printf(logger.INFO, "[%s] No validator defined for block type %s", label, msg.BType)
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
		logger.Printf(logger.DBG, "[%s] Actions: closest=%v, demux=%v => doStore=%v, doForward=%v",
			label, closest, demux, doStore, doForward)

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
		if msg.BType == enums.BLOCK_TYPE_DHT_HELLO {
			m.addSender(msg.Block, label, sender)
		}
		//--------------------------------------------------------------
		// check if we need to forward
		if doForward {
			// add local node to filter
			pf.Add(local)

			// forward to computed number of peers
			numForward := m.rtable.ComputeOutDegree(msg.ReplLvl, msg.HopCount)
			for n := 0; n < numForward; n++ {
				if p := m.rtable.SelectPeer(addr, msg.HopCount, pf, 0); p != nil {
					// check if route is recorded (9.3.2.6)
					var pp *path.Path
					if msg.Flags&enums.DHT_RO_RECORD_ROUTE != 0 {
						// yes: add path element
						pp = entry.Path.Clone()
						pe := pp.NewElement(sender, local, p.Peer)
						if err := m.core.Sign(pe); err != nil {
							logger.Printf(logger.ERROR, "[%s] failed to sign path element: %s", label, err.Error())
						} else {
							pp.Add(pe)
						}
					}
					// build updated PUT message
					msgOut := msg.Update(pp, pf, msg.HopCount+1)

					// forward message to peer
					logger.Printf(logger.INFO, "[%s] forward PUT message to %s", label, p.Peer.Short())
					if err := m.core.Send(ctx, p.Peer, msgOut); err != nil {
						logger.Printf(logger.ERROR, "[%s] Failed to forward PUT message: %s", label, err.Error())
					}
					// add forward node to filter
					pf.Add(p.Peer)
				} else {
					break
				}
			}
		}
		logger.Printf(logger.INFO, "[%s] DHT-P2P-PUT done", label)

	//==================================================================
	// DHT-P2P-RESULT
	//==================================================================
	case *message.DHTP2PResultMsg:
		//----------------------------------------------------------
		// DHT-P2P RESULT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] DHT-P2P-RESULT from %s (type %s, flags=%s)",
			label, sender.Short(), msg.BType, message.DHTFlags(msg.Flags))

		//--------------------------------------------------------------
		// check if request is expired (9.5.2.1)
		if msg.Expire.Expired() {
			logger.Printf(logger.WARN, "[%s] message expired (%s) -- ignoring",
				label, msg.Expire.String())
			return false
		}
		//--------------------------------------------------------------
		btype := msg.BType
		var blkKey *crypto.HashCode
		blockHdlr, ok := blocks.BlockHandlers[btype]
		if ok {
			// reconstruct block instance
			if block, err := blockHdlr.ParseBlock(msg.Block); err == nil {
				// validate block (9.5.2.2)
				if !blockHdlr.ValidateBlockStoreRequest(block) {
					logger.Printf(logger.WARN, "[%s] RESULT invalid block -- discarded", label)
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
			m.addSender(msg.Block, label, sender)
		}
		// message forwarding to responder
		logger.Printf(logger.DBG, "[%s] result key = %s", label, msg.Query.Short())
		handled := false
		key := msg.Query.String()
		if list, ok := m.reshdlrs.Get(key); ok {
			for _, rh := range list {
				logger.Printf(logger.DBG, "[%s] Result handler task #%d found (receiver %s)", label, rh.ID(), rh.Receiver().Short())

				// check if the handler can really handle the result
				if rh.Type() != btype {
					// this is another block type, we don't handle it
					logger.Printf(logger.DBG, "[%s] Result handler not suitable (%s != %s) -- skipped", label, rh.Type(), btype)
					continue
				}
				if rh.Flags()&enums.DHT_RO_FIND_APPROXIMATE == 0 && msg.Flags&enums.DHT_RO_FIND_APPROXIMATE != 0 {
					logger.Printf(logger.DBG, "[%s] Result handler asked for match, got approx -- ignored", label)
					continue
				}
				//--------------------------------------------------------------
				// check task list for handler (9.5.2.6)
				if rh.Flags()&enums.DHT_RO_FIND_APPROXIMATE == 0 && blkKey != nil && !blkKey.Equal(rh.Key()) {
					// (9.5.2.6.a) derived key mismatch
					logger.Printf(logger.ERROR, "[%s] derived block key / query key mismatch:", label)
					logger.Printf(logger.ERROR, "[%s]   --> %s != %s", label, blkKey, rh.Key())
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
			logger.Printf(logger.WARN, "[%s] RESULT not processed (no handler)", label)
		} else {
			logger.Printf(logger.INFO, "[%s] DHT-P2P-RESULT done", label)
		}
		return handled

	//==================================================================
	// DHT-P2P-HELLO
	//==================================================================
	case *message.DHTP2PHelloMsg:
		//----------------------------------------------------------
		// DHT-P2P HELLO
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] DHT-P2P-HELLO from %s", label, sender.Short())

		// verify integrity of message
		if ok, err := msg.Verify(sender); !ok || err != nil {
			logger.Printf(logger.WARN, "[%s] Received invalid HELLO message", label)
			if err != nil {
				logger.Printf(logger.ERROR, "[%s] --> %s", label, err.Error())
			}
			return false
		}
		// keep peer addresses in core for transports
		aList, err := msg.Addresses()
		if err != nil {
			logger.Printf(logger.ERROR, "[%s] Failed to parse addresses from HELLO message", label)
			return false
		}
		if newPeer := m.core.Learn(ctx, sender, aList, label); newPeer {
			// we added a previously unknown peer: send a HELLO
			var msgOut *message.DHTP2PHelloMsg
			if msgOut, err = m.getHello(label); err != nil {
				return false
			}
			logger.Printf(logger.INFO, "[%s] Sending own HELLO to %s", label, sender.Short())
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
			logger.Printf(logger.INFO, "[%s] caching HELLO from %s", label, sender.Short())
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
		logger.Printf(logger.INFO, "[%s] Ignoring DHTClientPut message", label)

	case *message.DHTClientGetMsg:
		//----------------------------------------------------------
		// DHT GET
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Ignoring DHTClientGet message", label)

	case *message.DHTClientGetResultsKnownMsg:
		//----------------------------------------------------------
		// DHT GET-RESULTS-KNOWN
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Ignoring DHTClientGetResultsKnown message", label)

	case *message.DHTClientGetStopMsg:
		//----------------------------------------------------------
		// DHT GET-STOP
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Ignoring DHTClientGetStop message", label)

	case *message.DHTClientResultMsg:
		//----------------------------------------------------------
		// DHT RESULT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Ignoring DHTClientResult message", label)

	default:
		//----------------------------------------------------------
		// UNKNOWN message type received
		//----------------------------------------------------------
		logger.Printf(logger.ERROR, "[%s] Unhandled message of type (%s)\n", label, msgIn.Type())
		return false
	}
	return true
}

//----------------------------------------------------------------------
// Helpers
//----------------------------------------------------------------------

// add a HELLO block sender to routing table
func (m *Module) addSender(block []byte, label string, sender *util.PeerID) {
	// get addresses from HELLO block
	hello, err := blocks.ParseHelloBlockFromBytes(block)
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

// send a result back to caller
func (m *Module) sendResult(ctx context.Context, query blocks.Query, blk blocks.Block, pth *path.Path, back transport.Responder) error {
	// assemble result message
	out := message.NewDHTP2PResultMsg()
	out.BType = query.Type()
	out.Flags = query.Flags()
	out.Expire = blk.Expire()
	out.Query = query.Key()
	out.Block = blk.Bytes()
	out.MsgSize += uint16(len(out.Block))
	out.SetPath(pth)
	/*
		// DEBUG:
		if out.BType == enums.BLOCK_TYPE_TEST {
			logger.Printf(logger.DBG, "result message = %s", util.Dump(out, "hex"))
			logger.Printf(logger.DBG, "result message = %s", util.Dump(out, "json"))
		}
	*/
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
