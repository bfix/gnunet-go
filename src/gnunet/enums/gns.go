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
// Resource Record Flags
//----------------------------------------------------------------------

// GNSFlag type
type GNSFlag uint16

const (
	// GNS record flags
	GNS_FLAG_CRITICAL GNSFlag = 1     // Record is critical (abort processing if RR type is not supoorted)
	GNS_FLAG_SHADOW   GNSFlag = 2     // Record is ignored if non-expired records of same type exist in block
	GNS_FLAG_SUPPL    GNSFlag = 4     // Supplemental records (e.g. NICK) in a block
	GNS_FLAG_EXPREL   GNSFlag = 16384 // Expiry time is relative
	GNS_FLAG_PRIVATE  GNSFlag = 32768 // Record is not shared on the DHT
)

// List flags as strings
func (gf GNSFlag) List() (flags []string) {
	if gf&GNS_FLAG_PRIVATE != 0 {
		flags = append(flags, "Private")
	}
	if gf&GNS_FLAG_SHADOW != 0 {
		flags = append(flags, "Shadow")
	}
	if gf&GNS_FLAG_SUPPL != 0 {
		flags = append(flags, "Suppl")
	}
	if gf&GNS_FLAG_CRITICAL != 0 {
		flags = append(flags, "Critical")
	}
	if gf&GNS_FLAG_EXPREL != 0 {
		flags = append(flags, "TTL")
	}
	return
}

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
