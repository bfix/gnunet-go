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

//----------------------------------------------------------------------
// GNS filters
//----------------------------------------------------------------------

type GNSFilter uint16

const (
	// GNS filters
	GNS_FILTER_NONE                GNSFilter = 0
	GNS_FILTER_INCLUDE_MAINTENANCE GNSFilter = 1
	GNS_FILTER_OMIT_PRIVATE        GNSFilter = 2
)

//----------------------------------------------------------------------
// GNS type/flag combination (spec)
//----------------------------------------------------------------------

// GNSSpec is the combination of type and flags
type GNSSpec struct {
	Type  GNSType
	Flags GNSFlag
}

//----------------------------------------------------------------------
// Local settings
//----------------------------------------------------------------------

const (
	// GNS_LocalOptions
	GNS_LO_DEFAULT      = 0 // Defaults, look in cache, then in DHT.
	GNS_LO_NO_DHT       = 1 // Never look in the DHT, keep request to local cache.
	GNS_LO_LOCAL_MASTER = 2 // For the rightmost label, only look in the cache.

	GNS_MAX_BLOCK_SIZE = (63 * 1024) // Maximum size of a value that can be stored in a GNS block.

	GNS_REPLICATION_LEVEL = 10
)
