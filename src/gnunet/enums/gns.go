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

// GNSFlag type
type GNSFlag uint32

const (
	// GNS record flags
	GNS_FLAG_PRIVATE GNSFlag = 2  // Record is not shared on the DHT
	GNS_FLAG_SUPPL   GNSFlag = 4  // Supplemental records (e.g. NICK) in a block
	GNS_FLAG_EXPREL  GNSFlag = 8  // Expire time in record is in relative time.
	GNS_FLAG_SHADOW  GNSFlag = 16 // Record is ignored if non-expired records of same type exist in block

	// GNS_LocalOptions
	GNS_LO_DEFAULT      = 0 // Defaults, look in cache, then in DHT.
	GNS_LO_NO_DHT       = 1 // Never look in the DHT, keep request to local cache.
	GNS_LO_LOCAL_MASTER = 2 // For the rightmost label, only look in the cache.

	GNS_MAX_BLOCK_SIZE = (63 * 1024) // Maximum size of a value that can be stored in a GNS block.

	GNS_REPLICATION_LEVEL = 10
)

//go:generate go run generate/main.go gnunet-gns.rec gnunet-gns.tpl gns_type.go

//go:generate stringer -type=GNSType gns_type.go

// GNSSpec is the combination of type and flags
type GNSSpec struct {
	Type  GNSType
	Flags GNSFlag
}
