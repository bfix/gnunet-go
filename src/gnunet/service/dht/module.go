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
	reshdlrs  *ResultHandlerList      // list of open tasks
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
		reshdlrs:   NewResultHandlerList(),
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
	return m.store.Put(key, block)
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

	// clean-up task list
	m.reshdlrs.Cleanup()
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

// SetNetworkSize sets a fixed number of peers in the network
func (m *Module) SetNetworkSize(numPeers int) {
	m.rtable.l2nse = gmath.Log2(float64(numPeers))
}
