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

package enums

//----------------------------------------------------------------------
// Signature purposes
//----------------------------------------------------------------------

//go:generate go run generate/main.go gnunet-signature.rec gnunet-signature.tpl signature_purpose.go

//go:generate stringer -type=SigPurpose signature_purpose.go

//----------------------------------------------------------------------
// Error codes
//----------------------------------------------------------------------

//go:generate go run generate/main.go gnunet-error-codes.rec gnunet-error-codes.tpl error_codes.go

//go:generate stringer -type=ErrorCode error_codes.go

//----------------------------------------------------------------------
// DHT block types
//----------------------------------------------------------------------

//go:generate go run generate/main.go gnunet-dht.rec gnunet-dht.tpl dht_block_type.go

//go:generate stringer -type=BlockType dht_block_type.go

//----------------------------------------------------------------------
// GNS record types
//----------------------------------------------------------------------

//go:generate go run generate/main.go gnunet-gns.rec gnunet-gns.tpl gns_type.go

//go:generate stringer -type=GNSType gns_type.go
