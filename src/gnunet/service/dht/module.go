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
	"gnunet/config"
	"gnunet/core"
	"gnunet/message"
	"gnunet/service"
	"gnunet/service/dht/blocks"
	"gnunet/transport"
	"gnunet/util"
	"time"

	"github.com/bfix/gospel/logger"
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

	store service.DHTStore // reference to the block storage mechanism
	cache service.DHTStore // transient block cache
	core  *core.Core       // reference to core services

	rtable     *RoutingTable                 // routing table
	helloCache map[string]*blocks.HelloBlock // HELLO block cache
}

// NewModule returns a new module instance. It initializes the storage
// mechanism for persistence.
func NewModule(ctx context.Context, c *core.Core) (m *Module, err error) {
	// create permanent storage handler
	var store, cache service.DHTStore
	if store, err = service.NewDHTStore(config.Cfg.DHT.Storage); err != nil {
		return
	}
	// create routing table
	rt := NewRoutingTable(NewPeerAddress(c.PeerID()))

	// return module instance
	m = &Module{
		ModuleImpl: *service.NewModuleImpl(),
		store:      store,
		cache:      cache,
		core:       c,
		rtable:     rt,
		helloCache: make(map[string]*blocks.HelloBlock),
	}
	// register as listener for core events
	listener := m.Run(ctx, m.event, m.Filter(), 15*time.Minute, m.heartbeat)
	c.Register("dht", listener)
	return
}

//----------------------------------------------------------------------

// Get a block from the DHT ["dht:get"]
func (m *Module) Get(ctx context.Context, query blocks.Query) (block blocks.Block, err error) {

	// check if we have the requested block in cache or permanent storage.
	block, err = m.cache.Get(query)
	if err == nil {
		// yes: we are done
		return
	}
	block, err = m.store.Get(query)
	if err == nil {
		// yes: we are done
		return
	}
	// retrieve the block from the DHT

	return nil, nil
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
		// delete from HELLO cache
		delete(m.helloCache, ev.Peer.String())

	// Message received.
	case core.EV_MESSAGE:
		logger.Printf(logger.INFO, "[dht] Message received: %s", ev.Msg.String())

		// handle HELLO messages directly (we need to do it here because the
		// standard processing has no access to the PeerID of the sender as
		// it is not part of the message).
		if ev.Msg.Header().MsgType == message.DHT_P2P_HELLO {
			msg := ev.Msg.(*message.DHTP2PHelloMsg)

			// check if peer is in routing table
			if !m.rtable.Contains(NewPeerAddress(ev.Peer)) {
				logger.Println(logger.WARN, "[dht] DHT_P2P_HELLO from unregistered peer -- discarded")
				return
			}

			// verify integrity of message
			if ok, err := msg.Verify(ev.Peer); !ok || err != nil {
				logger.Println(logger.WARN, "[dht] Received invalid DHT_P2P_HELLO message")
				return
			}
			// keep peer addresses in core for transport
			aList, err := msg.Addresses()
			if err != nil {
				logger.Println(logger.WARN, "[dht] Failed to parse addresses from DHT_P2P_HELLO message")
				return
			}
			if err := m.core.Learn(ctx, ev.Peer, aList); err != nil {
				logger.Println(logger.WARN, "[dht] Failed to learn addresses from DHT_P2P_HELLO message: "+err.Error())
				return
			}

			// cache HELLO block if applicable
			k := ev.Peer.String()
			isNew := true
			if hb, ok := m.helloCache[k]; ok {
				// cache entry exists: is the HELLO message more recent?
				_, isNew = hb.Expire.Diff(msg.Expires)
			}
			// we need to cache a new(er) HELLO
			if isNew {
				m.helloCache[k] = &blocks.HelloBlock{
					PeerID:    ev.Peer,
					Signature: util.Clone(msg.Signature),
					Expire:    msg.Expires,
					AddrBin:   util.Clone(msg.AddrList),
				}
			}
			return
		}
		// process message
		if !m.HandleMessage(ctx, ev.Msg, ev.Resp) {
			logger.Println(logger.WARN, "[dht] Message NOT handled!")
		}
	}
}

// Heartbeat handler for periodic tasks
func (m *Module) heartbeat(ctx context.Context) {

	// drop expired entries from the HELLO cache
	for key, hb := range m.helloCache {
		if hb.Expire.Expired() {
			delete(m.helloCache, key)
		}
	}
	// update the estimated network size
	m.rtable.l2nse = m.core.L2NSE()

	// run heartbeat for routing table
	m.rtable.heartbeat(ctx)
}

//----------------------------------------------------------------------
// Inter-module linkage helpers
//----------------------------------------------------------------------

// Export functions
func (m *Module) Export(fcn map[string]any) {
	// add exported functions from module
	fcn["dht:get"] = m.Get
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
func (m *Module) HandleMessage(ctx context.Context, msg message.Message, back transport.Responder) bool {
	// assemble log label
	label := "dht"
	if v := ctx.Value("label"); v != nil {
		if s := v.(string); len(s) > 0 {
			label = "dht-" + s
		}
	}
	// process message
	switch m := msg.(type) {

	case *message.DHTP2PGetMsg:
		//----------------------------------------------------------
		// DHT-P2P GET
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-GET message", label)

		// validate query (based on block type reqested)
		validator, ok := blocks.BlockQueryValidation[m.MsgType]
		if ok {
			if !validator(m.Query, m.XQuery) {
				logger.Printf(logger.INFO, "[%s] DHT-P2P-GET message invalid -- discarded", label)
				return false
			}
		}

	case *message.DHTP2PPutMsg:
		//----------------------------------------------------------
		// DHT-P2P PUT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-PUT message", label)

	case *message.DHTP2PResultMsg:
		//----------------------------------------------------------
		// DHT RESULT
		//----------------------------------------------------------
		logger.Printf(logger.INFO, "[%s] Handling DHT-P2P-RESULT message", label)

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
