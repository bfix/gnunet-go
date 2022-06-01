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

//======================================================================
// Standalone (all-in-one) implementation of GNUnet:
// -------------------------------------------------
// Instead of running GNUnet services like GNS or DHT in separate
// processes communicating (exchanging messages) with each other over
// Unix Domain Sockets, the standalone implementation combines all
// service modules into a single binary running go-routines to
// concurrently performing their tasks.
//======================================================================

package gnunet

import (
	"gnunet/service/dht"
	"gnunet/service/gns"
	"gnunet/service/namecache"
	"gnunet/service/revocation"
	"net/rpc"
)

// Instances holds a list of all GNUnet service modules
type Instances struct {
	GNS        *gns.Module
	Namecache  *namecache.NamecacheModule
	DHT        *dht.Module
	Revocation *revocation.Module
}

// Register modules for JSON-RPC
func (inst Instances) Register() {
	rpc.Register(inst.GNS)
	rpc.Register(inst.Namecache)
	rpc.Register(inst.DHT)
	rpc.Register(inst.Revocation)
}

// Local reference to instance list. The list is initialized
// by core.
var (
	Modules Instances
)

/* TODO: implement
// Initialize instance list and link module functions as required.
// This function is called by core on start-up.
func Init(ctx context.Context) {

	// Namecache (no calls to other modules)
	Modules.Namecache = namecache.NewModule(ctx, c)

	// DHT (no calls to other modules)
	Modules.DHT = dht.NewModule(ctx, c)

	// Revocation (no calls to other modules)
	Modules.Revocation = revocation.NewModule(ctx, c)

	// GNS (calls Namecache, DHT and Identity)
	gns := gns.NewModule(ctx, c)
	Modules.GNS = gns
	gns.LookupLocal = Modules.Namecache.Get
	gns.StoreLocal = Modules.Namecache.Put
	gns.LookupRemote = Modules.DHT.Get
	gns.RevocationQuery = Modules.Revocation.Query
	gns.RevocationRevoke = Modules.Revocation.Revoke
}
*/
