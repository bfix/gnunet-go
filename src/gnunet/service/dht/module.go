// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
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
	"net/http"
	"time"
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

	rtable *RoutingTable // routing table
}

// NewModule returns a new module instance. It initializes the storage
// mechanism for persistence.
func NewModule(ctx context.Context, c *core.Core) (m *Module) {
	// create permanent storage handler
	store, err := service.NewDHTStore(config.Cfg.DHT.Storage)
	if err != nil {
		return nil
	}
	// create cache handler
	cache, err := service.NewDHTStore(config.Cfg.DHT.Cache)
	if err != nil {
		return nil
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
	}
	// register as listener for core events
	listener := m.Run(ctx, m.event, m.Filter(), 15*time.Minute, m.heartbeat)
	c.Register("dht", listener)

	return
}

//----------------------------------------------------------------------

// Get a block from the DHT
func (nc *Module) Get(ctx context.Context, query blocks.Query) (block blocks.Block, err error) {

	// check if we have the requested block in cache or permanent storage.
	block, err = nc.cache.Get(query)
	if err == nil {
		// yes: we are done
		return
	}
	block, err = nc.store.Get(query)
	if err == nil {
		// yes: we are done
		return
	}
	// retrieve the block from the DHT

	return nil, nil
}

// Put a block into the DHT
func (nc *Module) Put(ctx context.Context, key blocks.Query, block blocks.Block) error {
	return nil
}

//----------------------------------------------------------------------

// Filter returns the event filter for the module
func (m *Module) Filter() *core.EventFilter {
	f := core.NewEventFilter()
	f.AddEvent(core.EV_CONNECT)
	f.AddEvent(core.EV_DISCONNECT)
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

	}

}

// Heartbeat handler for periodic tasks
func (m *Module) heartbeat(ctx context.Context) {
	// update the estimated network size
	m.rtable.l2nse = m.core.L2NSE()

	// run heartbeat for routing table
	m.rtable.heartbeat(ctx)
}

//----------------------------------------------------------------------

// RPC returns the route and handler function for a JSON-RPC request
func (m *Module) RPC() (string, func(http.ResponseWriter, *http.Request)) {
	return "/gns/", func(wrt http.ResponseWriter, req *http.Request) {
		wrt.Write([]byte(`{"msg": "This is DHT" }`))
	}
}
