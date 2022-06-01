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

package namecache

import (
	"context"
	"gnunet/config"
	"gnunet/core"
	"gnunet/service"
	"gnunet/service/dht/blocks"
)

//======================================================================
// "GNS name cache" implementation
//======================================================================

//----------------------------------------------------------------------
// Put and get GNS blocks into/from a cache (transient storage)
//----------------------------------------------------------------------

// Namecache handles the transient storage of GNS blocks under the query key.
type NamecacheModule struct {
	service.ModuleImpl

	cache service.DHTStore // transient block cache
}

// NewModule creates a new module instance.
func NewModule(ctx context.Context, c *core.Core) (m *NamecacheModule) {
	m = &NamecacheModule{
		ModuleImpl: *service.NewModuleImpl(),
	}
	m.cache, _ = service.NewDHTStore(config.Cfg.Namecache.Storage)
	return
}

// Get an entry from the cache if available.
func (m *NamecacheModule) Get(ctx context.Context, query *blocks.GNSQuery) (block *blocks.GNSBlock, err error) {
	var b blocks.Block
	b, err = m.cache.Get(query)
	err = blocks.Unwrap(b, block)
	return
}

// Put entry into the cache.
func (m *NamecacheModule) Put(ctx context.Context, query *blocks.GNSQuery, block *blocks.GNSBlock) error {
	return m.cache.Put(query, block)
}
