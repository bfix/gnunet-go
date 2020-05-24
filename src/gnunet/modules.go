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
)

// List of all GNUnet service module instances
type Instances struct {
	GNS        *gns.GNSModule
	Namecache  *namecache.NamecacheModule
	DHT        *dht.DHTModule
	Revocation *revocation.RevocationModule
}

// Local reference to instance list
var (
	Modules Instances
)

// Initialize instance list and link module functions as required.
func init() {

	// Namecache (no calls to other modules)
	Modules.Namecache = new(namecache.NamecacheModule)

	// DHT (no calls to other modules)
	Modules.DHT = new(dht.DHTModule)

	// Revocation (no calls to other modules)
	Modules.Revocation = revocation.NewRevocationModule()

	// GNS (calls Namecache, DHT and Identity)
	Modules.GNS = &gns.GNSModule{
		LookupLocal:      Modules.Namecache.Get,
		StoreLocal:       Modules.Namecache.Put,
		LookupRemote:     Modules.DHT.Get,
		RevocationQuery:  Modules.Revocation.Query,
		RevocationRevoke: Modules.Revocation.Revoke,
	}
}
