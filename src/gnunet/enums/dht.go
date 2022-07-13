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

//nolint:stylecheck // allow non-camel-case for constants
package enums

// DHT flags and settings
const (
	DHT_RO_NONE                   = 0 // Default.  Do nothing special.
	DHT_RO_DEMULTIPLEX_EVERYWHERE = 1 // Each peer along the way should look at 'enc'
	DHT_RO_RECORD_ROUTE           = 2 // keep track of the route that the message took in the P2P network.
	DHT_RO_FIND_APPROXIMATE       = 4 // Approximate results are fine.
	DHT_RO_TRUNCATED              = 8 // Flag if path is truncated
)

//go:generate go run generate.go gnunet-dht.rec gnunet-dht.tpl dht_block_type.go

//go:generate stringer -type=BlockType dht_block_type.go
