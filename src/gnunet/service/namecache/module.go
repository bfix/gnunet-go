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

package namecache

import (
	"context"
	"errors"
	"gnunet/config"
	"gnunet/core"
	"gnunet/service"
	"gnunet/service/dht/blocks"
	"gnunet/service/store"
	"gnunet/util"
)

//======================================================================
// "GNS name cache" implementation
//======================================================================

//----------------------------------------------------------------------
// Put and get GNS blocks into/from a cache (transient storage)
//----------------------------------------------------------------------

// Namecache handles the transient storage of GNS blocks under the query key.
type Module struct {
	service.ModuleImpl

	cache *store.DHTStore // transient block cache
}

// NewModule creates a new module instance.
func NewModule(ctx context.Context, c *core.Core) (m *Module) {
	m = &Module{
		ModuleImpl: *service.NewModuleImpl(),
	}
	m.cache, _ = store.NewDHTStore(config.Cfg.Namecache.Storage)
	return
}

//----------------------------------------------------------------------

// Export functions
func (m *Module) Export(fcn map[string]any) {
	// add exported functions from module
	fcn["namecache:get"] = m.Get
	fcn["namecache:put"] = m.Put
}

// Import functions
func (m *Module) Import(fcm map[string]any) {
	// nothing to import now.
}

//----------------------------------------------------------------------

// Get entry from the cache if available.
func (m *Module) Get(ctx context.Context, query *blocks.GNSQuery) (block *blocks.GNSBlock, err error) {
	var e []*store.DHTEntry
	rf := blocks.NewGenericResultFilter(128, util.RndUInt32())
	if e, err = m.cache.Get("namecache", query, rf); err != nil {
		return
	}
	if len(e) != 1 {
		err = errors.New("only one namecache entry expected")
	} else {
		err = blocks.Unwrap(e[0].Blk, block)
	}
	return
}

// Put entry into the cache.
func (m *Module) Put(ctx context.Context, query *blocks.GNSQuery, entry *store.DHTEntry) error {
	return m.cache.Put(query, entry)
}
