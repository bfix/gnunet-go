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
	"gnunet/config"
	"gnunet/service"
	"gnunet/service/dht/blocks"
	"net/http"
)

//======================================================================
// "DHT" implementation
//======================================================================

//----------------------------------------------------------------------
// Put and get blocks into/from a DHT.
//----------------------------------------------------------------------

// Module handles the permanent storage of blocks under a query key.
type Module struct {
	store service.DHTStore // reference to the block storage mechanism
	cache service.DHTStore // transient block cache
}

// NewModule returns a new module instance. It initializes the storage
// mechanism for persistence.
func NewModule() *Module {
	store, err := service.NewDHTStore(config.Cfg.DHT.Storage)
	if err != nil {
		return nil
	}
	cache, err := service.NewDHTStore(config.Cfg.DHT.Cache)
	if err != nil {
		return nil
	}
	return &Module{
		store: store,
		cache: cache,
	}
}

// Get a block from the DHT
func (nc *Module) Get(ctx *service.SessionContext, key blocks.Query) (blocks.Block, error) {
	return nil, nil
}

// Put a block into the DHT
func (nc *Module) Put(ctx *service.SessionContext, key blocks.Query, block blocks.Block) error {
	return nil
}

// RPC returns the route and handler function for a JSON-RPC request
func (m *Module) RPC() (string, func(http.ResponseWriter, *http.Request)) {
	return "/gns/", func(wrt http.ResponseWriter, req *http.Request) {
		wrt.Write([]byte(`{"msg": "This is DHT" }`))
	}
}
