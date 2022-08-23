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

package crypto

import (
	"gnunet/enums"
	"gnunet/util"
)

// SignaturePurpose is the GNUnet data structure used as header for signed data.
type SignaturePurpose struct {
	Size    uint32           `order:"big"` // How many bytes are signed?
	Purpose enums.SigPurpose `order:"big"` // Signature purpose
}

// Signable interface for objects that can get signed by a Signer
type Signable interface {
	// SignedData returns the byte array to be signed
	SignedData() []byte

	// SetSignature returns the signature to the signable object
	SetSignature(*util.PeerSignature) error
}

// Signer instance for creating signatures
type Signer interface {
	Sign(Signable) error
}
