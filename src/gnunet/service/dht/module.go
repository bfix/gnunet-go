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
	"gnunet/message"
	"gnunet/service"
	"gnunet/service/gns"
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
}

// RPC returns the route and handler function for a JSON-RPC request
func (m *Module) RPC() (string, func(http.ResponseWriter, *http.Request)) {
	return "/gns/", func(wrt http.ResponseWriter, req *http.Request) {
		wrt.Write([]byte(`{"msg": "This is DHT" }`))
	}
}

// Get a block from the DHT
func (nc *Module) Get(ctx *service.SessionContext, query *gns.Query) (*message.Block, error) {
	return nil, nil
}

// Put a block into the DHT
func (nc *Module) Put(ctx *service.SessionContext, block *message.Block) error {
	return nil
}
