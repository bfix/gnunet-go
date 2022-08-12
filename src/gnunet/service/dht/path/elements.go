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

package path

import (
	"encoding/hex"
	"errors"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

// Error values
var (
	ErrPathNoSig = errors.New("missing signature for path element verification")
)

//----------------------------------------------------------------------
// Entry is an element of the path list
type Entry struct {
	Signature *util.PeerSignature // path element signature
	Signer    *util.PeerID        // path element signer
}

// Size returns the size of a path element in wire format
func (e *Entry) Size() uint {
	return e.Signer.Size() + e.Signature.Size()
}

// String returns a human-readable representation
func (e *Entry) String() string {
	s := hex.EncodeToString(e.Signature.Bytes())
	num := len(s)
	if num > 16 {
		s = s[:8] + ".." + s[num-8:]
	}
	return fmt.Sprintf("(%s,%s)", e.Signer.String(), s)
}

//----------------------------------------------------------------------
// shared path element data across types
type elementData struct {
	Expiration      util.AbsoluteTime // expiration date
	BlockHash       *crypto.HashCode  // block hash
	PeerPredecessor *util.PeerID      // predecessor peer
	PeerSuccessor   *util.PeerID      // successor peer
}

// helper type for signature creation/verification
type elementSignedData struct {
	Size    uint16       `order:"big"` // size of signed data
	Purpose uint16       `order:"big"` // signature purpose (SIG_DHT_HOP)
	Elem    *elementData ``            // path element data
}

//----------------------------------------------------------------------
// Element is the full-fledged data assembly for a path element in
// PUT/GET pathes. It is assembled programatically (on generation[1] and
// verification[2]) and not transferred in messages directly.
//
// [1] spe = &Element{...}
//     core.Sign(spe)
//     msg.putpath[i] = spe.Wire()
//
// [2] pe = &Element{...,Signature: wire.sig}
//     if !pe.Verify(peerId) { ... }
//
type Element struct {
	elementData
	Entry
}

// SignedData gets the data to be signed by peer ('Signable' interface)
func (pe *Element) SignedData() []byte {
	sd := &elementSignedData{
		Size:    80,
		Purpose: uint16(enums.SIG_DHT_HOP),
		Elem:    &(pe.elementData),
	}
	buf, err := data.Marshal(sd)
	if err != nil {
		logger.Println(logger.ERROR, "can't serialize path element for signature")
		return nil
	}
	return buf
}

// SetSignature stores the generated signature.
func (pe *Element) SetSignature(sig *util.PeerSignature) error {
	pe.Signature = sig
	return nil
}

// Wire returns the path element suitable for inclusion into messages
func (pe *Element) Wire() *Entry {
	return &(pe.Entry)
}

// Verify signature for a path element. If the signature argument
// is zero, use the signature store with the element
func (pe *Element) Verify(sig *util.PeerSignature) (bool, error) {
	if sig == nil {
		sig = pe.Signature
		if sig == nil {
			return false, ErrPathNoSig
		}
	}
	return pe.Signer.Verify(pe.SignedData(), sig)
}
