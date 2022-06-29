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
	"errors"
	"gnunet/config"
	"gnunet/core"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service"
	"gnunet/service/dht/blocks"
	"gnunet/service/store"
	"gnunet/transport"
	"gnunet/util"
	gmath "math"
	"time"

	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/math"
)

//======================================================================
// "DHT" implementation
//======================================================================

//----------------------------------------------------------------------
// Put and get blocks into/from a DHT.
//----------------------------------------------------------------------

// Module handles the permanent storage of blocks under a query key.
type Module struct {
	service.ModuleImpl

	store store.DHTStore // reference to the block storage mechanism
	core  *core.Core     // reference to core services

	rtable    *RoutingTable           // routing table
	lastHello *message.DHTP2PHelloMsg // last own HELLO message used; re-create if expired
}

// NewModule returns a new module instance. It initializes the storage
// mechanism for persistence.
func NewModule(ctx context.Context, c *core.Core, cfg *config.DHTConfig) (m *Module, err error) {
	// create permanent storage handler
	var storage store.DHTStore
	if storage, err = store.NewDHTStore(cfg.Storage); err != nil {
		return
	}
	// create routing table
	rt := NewRoutingTable(NewPeerAddress(c.PeerID()), cfg.Routing)

	// return module instance
	m = &Module{
		ModuleImpl: *service.NewModuleImpl(),
		store:      storage,
		core:       c,
		rtable:     rt,
	}
	// register as listener for core events
	pulse := time.Duration(cfg.Heartbeat) * time.Second
	listener := m.Run(ctx, m.event, m.Filter(), pulse, m.heartbeat)
	c.Register("dht", listener)
	return
}

//----------------------------------------------------------------------

// Get a block from the DHT ["dht:get"]
func (m *Module) Get(ctx context.Context, query blocks.Query) (block blocks.Block, err error) {
	return m.store.Get(query)
}

// GetApprox returns the first block not excluded ["dht:getapprox"]
func (m *Module) GetApprox(ctx context.Context, query blocks.Query, excl func(blocks.Block) bool) (block blocks.Block, dist *math.Int, err error) {
	var d any
	block, d, err = m.store.GetApprox(query, excl)
	dist = d.(*math.Int)
	return
}

// Put a block into the DHT ["dht:put"]
func (m *Module) Put(ctx context.Context, key blocks.Query, block blocks.Block) error {
	return nil
}

//----------------------------------------------------------------------

// Filter returns the event filter for the module
func (m *Module) Filter() *core.EventFilter {
	f := core.NewEventFilter()
	// events we are interested in
	f.AddEvent(core.EV_CONNECT)
	f.AddEvent(core.EV_DISCONNECT)

	// messages we are interested in:
	// (1) DHT_P2P messages
	f.AddMsgType(message.DHT_P2P_PUT)
	f.AddMsgType(message.DHT_P2P_GET)
	f.AddMsgType(message.DHT_P2P_RESULT)
	f.AddMsgType(message.DHT_P2P_HELLO)
	// (2) DHT messages (legacy, not implemented)
	f.AddMsgType(message.DHT_CLIENT_GET)
	f.AddMsgType(message.DHT_CLIENT_GET_RESULTS_KNOWN)
	f.AddMsgType(message.DHT_CLIENT_GET_STOP)
	f.AddMsgType(message.DHT_CLIENT_PUT)
	f.AddMsgType(message.DHT_CLIENT_RESULT)

	return f
}

// Event handler for infrastructure signals
func (m *Module) event(ctx context.Context, ev *core.Event) {
	switch ev.ID {
	// New peer connected:
	case core.EV_CONNECT:
		// Add peer to routing table
		logger.Printf(logger.INFO, "[dht] Peer %s connected", ev.Peer)
		m.rtable.Add(NewPeerAddress(ev.Peer))

	// Peer disconnected:
	case core.EV_DISCONNECT:
		// Remove peer from routing table
		logger.Printf(logger.INFO, "[dht] Peer %s disconnected", ev.Peer)
		m.rtable.Remove(NewPeerAddress(ev.Peer))

	// Message received.
	case core.EV_MESSAGE:
		logger.Printf(logger.INFO, "[dht] Message received: %s", ev.Msg.String())

		// check if peer is in routing table (connected peer)
		if !m.rtable.Contains(NewPeerAddress(ev.Peer)) {
			logger.Printf(logger.WARN, "[dht] message %d from unregistered peer -- discarded", ev.Msg.Header().MsgType)
			return
		}
		// process message
		if !m.HandleMessage(ctx, ev.Peer, ev.Msg, ev.Resp) {
			logger.Println(logger.WARN, "[dht] Message NOT handled!")
		}
	}
}

// Heartbeat handler for periodic tasks
func (m *Module) heartbeat(ctx context.Context) {
	// run heartbeat for routing table
	m.rtable.heartbeat(ctx)
}

// Send the currently active HELLO to given network address
func (m *Module) SendHello(ctx context.Context, addr *util.Address) (err error) {
	// get (buffered) HELLO
	var msg *message.DHTP2PHelloMsg
	if msg, err = m.getHello(); err != nil {
		return
	}
	logger.Printf(logger.INFO, "[core] Sending HELLO to %s: %s", addr.URI(), msg)
	return m.core.SendToAddr(ctx, addr, msg)
}

// get the recent HELLO if it is defined and not expired;
// create a new HELLO otherwise.
func (m *Module) getHello() (msg *message.DHTP2PHelloMsg, err error) {
	if m.lastHello == nil || m.lastHello.Expires.Expired() {
		// assemble new (signed) HELLO block
		var addrList []*util.Address
		if addrList, err = m.core.Addresses(); err != nil {
			return
		}
		// assemble HELLO data
		hb := new(blocks.HelloBlock)
		hb.PeerID = m.core.PeerID()
		hb.Expires = util.NewAbsoluteTime(time.Now().Add(message.HelloAddressExpiration))
		hb.SetAddresses(addrList)

		// sign HELLO block
		if err = m.core.Sign(hb); err != nil {
			return
		}
		// assemble HELLO message
		msg = message.NewDHTP2PHelloMsg()
		msg.Expires = hb.Expires
		msg.SetAddresses(hb.Addresses())
		if err = m.core.Sign(msg); err != nil {
			return
		}

		// save for later use
		m.lastHello = msg

		// DEBUG
		var ok bool
		if ok, err = msg.Verify(m.core.PeerID()); !ok || err != nil {
			if !ok {
				err = errors.New("failed to verify own HELLO")
			}
			logger.Println(logger.ERROR, err.Error())
			return
		}
		logger.Println(logger.DBG, "[dht] New HELLO: "+transport.Dump(msg, "hex"))
		return
	}
	// we have a valid HELLO for re-use.
	return m.lastHello, nil
}

//----------------------------------------------------------------------
// Inter-module linkage helpers
//----------------------------------------------------------------------

// Export functions
func (m *Module) Export(fcn map[string]any) {
	// add exported functions from module
	fcn["dht:get"] = m.Get
	fcn["dht:getapprox"] = m.GetApprox
	fcn["dht:put"] = m.Put
}

// Import functions
func (m *Module) Import(fcn map[string]any) {
	// nothing to import for now.
}

//----------------------------------------------------------------------
// Handle DHT messages from the network
//----------------------------------------------------------------------

// HandleMessage handles a DHT request/response message. Responses are sent
// to the specified responder.
func (m *Module) HandleMessage(ctx context.Context, sender *util.PeerID, msg message.Message, back transport.Responder) bool {
	// assemble log label
	label := "dht"
	if v := ctx.Value("label"); v != nil {
		if s := v.(string); len(s) > 0 {
			label = "dht-" + s
		}
	}
	// process message
	switch msgT := msg.(type) {

	case *message.DHTP2PGetMsg:
		//--------------------------------------------------------------
		// DHT-P2P GET
		//--------------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-GET message", label)
		query := blocks.NewGenericQuery(msgT.Query.Bits, enums.BlockType(msgT.BType), msgT.Flags)

		var block blocks.Block
		var dist *math.Int
		var err error

		//--------------------------------------------------------------
		// validate query (based on block type requested)  (9.4.3.1)
		btype := enums.BlockType(msgT.BType)
		blockHdlr, ok := blocks.BlockHandlers[btype]
		if ok {
			// validate block query
			if !blockHdlr.ValidateBlockQuery(msgT.Query, msgT.XQuery) {
				logger.Printf(logger.WARN, "[%s] DHT-P2P-GET invalid query -- discarded", label)
				return false
			}
		} else {
			logger.Printf(logger.INFO, "[%s] No validator defined for block type %s", label, btype.String())
		}
		//----------------------------------------------------------
		// check if sender is in peer filter (9.4.3.2)
		if !msgT.PeerFilter.Contains(sender) {
			logger.Printf(logger.WARN, "[dht] Sender not in peer filter")
		}
		// parse result filter
		var rf blocks.ResultFilter = new(blocks.PassResultFilter)
		if msgT.ResFilter != nil && len(msgT.ResFilter) > 0 {
			rf = blocks.NewHelloResultFilterFromBytes(msgT.ResFilter)
		}
		// clone peer filter
		pf := msgT.PeerFilter.Clone()

		//----------------------------------------------------------
		// check if we need to respond (and how) (9.4.3.3)
		addr := NewQueryAddress(msgT.Query)
		closest := m.rtable.IsClosestPeer(nil, addr, msgT.PeerFilter)
		demux := int(msgT.Flags)&enums.DHT_RO_DEMULTIPLEX_EVERYWHERE != 0
		approx := int(msgT.Flags)&enums.DHT_RO_FIND_APPROXIMATE != 0
		// actions
		do_result := closest || (demux && approx)
		do_forward := !closest || (demux && !approx)
		logger.Printf(logger.DBG, "[dht] GET message: closest=%v, demux=%v, approx=%v --> result=%v, forward=%v",
			closest, demux, approx, do_result, do_forward)

		//------------------------------------------------------
		// query for a HELLO? (9.4.3.3a)
		if msgT.BType == uint32(enums.BLOCK_TYPE_DHT_URL_HELLO) {
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
			switch blockHdlr.FilterResult(block, query.Key(), rf, msgT.XQuery) {
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
			outMsg := msgT.Update(pf, rf, msgT.HopCount+1)

			// forward to number of peers
			numForward := m.rtable.ComputeOutDegree(msgT.ReplLevel, msgT.HopCount)
			key := NewQueryAddress(query.Key())
			for n := 0; n < numForward; n++ {
				if p := m.rtable.SelectClosestPeer(key, pf); p != nil {
					logger.Printf(logger.INFO, "[dht] forward DHT get message to %s", p.String())
					if err := back.Send(ctx, outMsg); err != nil {
						logger.Println(logger.ERROR, "[dht] Failed to forward DHT get message: "+err.Error())
					}
					pf.Add(p.Peer)
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

	case *message.DHTP2PHelloMsg:
		//----------------------------------------------------------
		// DHT-P2P HELLO
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-HELLO message", label)

		// verify integrity of message
		if ok, err := msgT.Verify(sender); !ok || err != nil {
			logger.Println(logger.WARN, "[dht] Received invalid DHT_P2P_HELLO message")
			if err != nil {
				logger.Println(logger.ERROR, "[dht] --> "+err.Error())
			}
			return false
		}
		// keep peer addresses in core for transport
		aList, err := msgT.Addresses()
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
			_, isNew = hb.Expires.Diff(msgT.Expires)
		}
		// we need to cache a new(er) HELLO
		if isNew {
			m.rtable.CacheHello(&blocks.HelloBlock{
				PeerID:    sender,
				Signature: msgT.Signature,
				Expires:   msgT.Expires,
				AddrBin:   util.Clone(msgT.AddrList),
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
		logger.Printf(logger.ERROR, "[%s] Unhandled message of type (%d)\n", label, msg.Header().MsgType)
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

// SetNetworkSize sets a fixed number of peers in the network
func (m *Module) SetNetworkSize(numPeers int) {
	m.rtable.l2nse = gmath.Log2(float64(numPeers))
}
