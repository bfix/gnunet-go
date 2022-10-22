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

package zonemaster

import (
	"context"

	"gnunet/core"
	"gnunet/enums"
	"gnunet/service"
	"gnunet/service/dht/blocks"
)

//======================================================================
// "GNUnet Zonemaster" implementation
//======================================================================

// Module handles namestore and identity requests.
type Module struct {
	service.ModuleImpl

	// Use function references for calls to methods in other modules:
	StoreLocal  func(ctx context.Context, query *blocks.GNSQuery, block *blocks.GNSBlock) error
	StoreRemote func(ctx context.Context, query blocks.Query, block blocks.Block) error
}

// NewModule instantiates a new GNS module.
func NewModule(ctx context.Context, c *core.Core) (m *Module) {
	m = &Module{
		ModuleImpl: *service.NewModuleImpl(),
	}
	if c != nil {
		// register as listener for core events
		listener := m.ModuleImpl.Run(ctx, m.event, m.Filter(), 0, nil)
		c.Register("zonemaster", listener)
	}
	return
}

//----------------------------------------------------------------------

// Filter returns the event filter for the service
func (m *Module) Filter() *core.EventFilter {
	f := core.NewEventFilter()
	f.AddMsgType(enums.MSG_NAMESTORE_ZONE_ITERATION_START)
	return f
}

// Event handler
func (m *Module) event(ctx context.Context, ev *core.Event) {

}

//----------------------------------------------------------------------

// Export functions
func (m *Module) Export(fcn map[string]any) {
	// add exported functions from module
}

// Import functions
func (m *Module) Import(fcn map[string]any) {
	// resolve imports from other modules
	m.StoreLocal, _ = fcn["namecache:put"].(func(ctx context.Context, query *blocks.GNSQuery, block *blocks.GNSBlock) error)
	m.StoreRemote, _ = fcn["dht:put"].(func(ctx context.Context, query blocks.Query, block blocks.Block) error)
}

//----------------------------------------------------------------------
