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

package blocks

import (
	"errors"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

// Error messages
var (
	ErrBlockNotDecrypted    = errors.New("GNS block not decrypted")
	ErrBlockInvalidSig      = errors.New("invalid signature key for GNS Block")
	ErrBlockTypeNotVerified = errors.New("can't verify block type")
	ErrBlockCantDecrypt     = errors.New("can't decrypt block type")
)

//----------------------------------------------------------------------
// Query key for GNS lookups
//----------------------------------------------------------------------

// GNSQuery specifies the context for a basic GNS name lookup of an (atomic)
// label in a given zone identified by its public key.
type GNSQuery struct {
	GenericQuery
	Zone    *crypto.ZoneKey // Public zone key
	Label   string          // Atomic label
	derived *crypto.ZoneKey // Derived zone key from (pkey,label)
}

// Verify the integrity of the block data from a signature.
func (q *GNSQuery) Verify(b Block) (err error) {
	switch blk := b.(type) {
	case *GNSBlock:
		// Integrity check performed
		blk.checked = true

		// verify derived key
		dkey := blk.DerivedKeySig.ZoneKey
		var dkey2 *crypto.ZoneKey
		if dkey2, _, err = q.Zone.Derive(q.Label, "gns"); err != nil {
			return
		}
		if !dkey.Equal(dkey2) {
			err = ErrBlockInvalidSig
			return
		}
		// verify signature
		var buf []byte
		if buf, err = data.Marshal(blk.Body); err != nil {
			return
		}
		blk.verified, err = blk.DerivedKeySig.Verify(buf)

	default:
		err = ErrBlockTypeNotVerified
	}
	return
}

// Decrypt block data with a key derived from zone key and label.
func (q *GNSQuery) Decrypt(b Block) (err error) {
	switch blk := b.(type) {
	case *GNSBlock:
		// decrypt GNS payload
		blk.data, err = q.Zone.Decrypt(blk.Body.Data, q.Label, blk.Body.Expire)
		blk.decrypted = true
		return

	default:
		err = ErrBlockCantDecrypt
	}
	return
}

// NewGNSQuery assembles a new Query object for the given zone and label.
func NewGNSQuery(zkey *crypto.ZoneKey, label string) *GNSQuery {
	// derive a public key from (pkey,label) and set the repository
	// key as the SHA512 hash of the binary key representation.
	// (key blinding)
	pd, _, err := zkey.Derive(label, "gns")
	if err != nil {
		logger.Printf(logger.ERROR, "[NewGNSQuery] failed: %s", err.Error())
	}
	gq := crypto.Hash(pd.Bytes())
	return &GNSQuery{
		GenericQuery: *NewGenericQuery(gq, enums.BLOCK_TYPE_GNS_NAMERECORD, 0),
		Zone:         zkey,
		Label:        label,
		derived:      pd,
	}
}

//----------------------------------------------------------------------
// GNS blocks
//----------------------------------------------------------------------

// SignedGNSBlockData represents the signed content of a GNS block
type SignedGNSBlockData struct {
	Purpose *crypto.SignaturePurpose ``         // Size and purpose of signature (8 bytes)
	Expire  util.AbsoluteTime        ``         // Expiration time of the block.
	Data    []byte                   `size:"*"` // Block data content
}

// GNSBlock is the result of GNS lookups for a given label in a zone.
// An encrypted and signed container for GNS resource records that represents
// the "atomic" data structure associated with a GNS label in a given zone.
type GNSBlock struct {

	// persistent
	DerivedKeySig *crypto.ZoneSignature // Derived key used for signing
	Body          *SignedGNSBlockData

	// transient data (not serialized)
	checked   bool   // block integrity checked
	verified  bool   // block signature verified (internal)
	decrypted bool   // block decrypted (internal)
	data      []byte // decrypted data
}

// Bytes return th binary representation of block
func (b *GNSBlock) Bytes() []byte {
	buf, _ := data.Marshal(b)
	return buf
}

// Expire returns the expiration date of the block.
func (b *GNSBlock) Expire() util.AbsoluteTime {
	return b.Body.Expire
}

// Type returns the requested block type
func (b *GNSBlock) Type() enums.BlockType {
	return enums.BLOCK_TYPE_GNS_NAMERECORD
}

// String returns the human-readable representation of a GNSBlock
func (b *GNSBlock) String() string {
	return fmt.Sprintf("GNSBlock{Verified=%v,Decrypted=%v,data=[%d]}",
		b.verified, b.decrypted, len(b.Body.Data))
}

// NewGNSBlock instantiates an empty GNS block
func NewGNSBlock() Block {
	return &GNSBlock{
		DerivedKeySig: nil,
		Body: &SignedGNSBlockData{
			Purpose: new(crypto.SignaturePurpose),
			Data:    nil,
		},
		checked:   false,
		verified:  false,
		decrypted: false,
		data:      nil,
	}
}

// Verify the integrity of the block data from a signature.
// Only the cryptographic signature is verified; the formal correctness of
// the association between the block and a GNS label in a GNS zone can't
// be verified. This is only possible in Query.Verify().
func (b *GNSBlock) Verify() (ok bool, err error) {
	// verify signature
	var buf []byte
	if buf, err = data.Marshal(b.Body); err != nil {
		return
	}
	return b.DerivedKeySig.Verify(buf)
}
