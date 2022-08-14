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

package util

import (
	"bytes"

	"github.com/bfix/gospel/crypto/ed25519"
)

//----------------------------------------------------------------------
// Peer public key (Ed25519 public key)
//----------------------------------------------------------------------

// PeerPublicKey is the binary representation of an Ed25519 public key
type PeerPublicKey struct {
	Data []byte `size:"(Size)"` // Ed25519 public key data
}

// NewPeerPublicKey creates a key instance from binary data
func NewPeerPublicKey(data []byte) *PeerPublicKey {
	pk := new(PeerPublicKey)
	size := pk.Size()
	v := make([]byte, size)
	if len(data) > 0 {
		if uint(len(data)) < size {
			CopyAlignedBlock(v, data)
		} else {
			copy(v, data[:size])
		}
	}
	pk.Data = v
	return pk
}

// Size returns the length of the binary data
func (pk *PeerPublicKey) Size() uint {
	return 32
}

// Verify peer signature
func (pk *PeerPublicKey) Verify(data []byte, sig *PeerSignature) (bool, error) {
	xpk := ed25519.NewPublicKeyFromBytes(pk.Data)
	xsig, err := ed25519.NewEdSignatureFromBytes(sig.Data)
	if err != nil {
		return false, err
	}
	return xpk.EdVerify(data, xsig)
}

//----------------------------------------------------------------------
// Peer identifier:
//----------------------------------------------------------------------

// PeerID is a wrapped PeerPublicKey
type PeerID struct {
	PeerPublicKey
}

// NewPeerID creates a new peer id from data.
func NewPeerID(data []byte) (p *PeerID) {
	return &PeerID{
		PeerPublicKey: *NewPeerPublicKey(data),
	}
}

// Equals returns true if two peer IDs match.
func (p *PeerID) Equals(q *PeerID) bool {
	return bytes.Equal(p.Data, q.Data)
}

// String returns a human-readable representation of a peer id.
func (p *PeerID) String() string {
	return EncodeBinaryToString(p.Data)
}

// Bytes returns the binary representation of a peer identifier.
func (p *PeerID) Bytes() []byte {
	return Clone(p.Data)
}

//----------------------------------------------------------------------
// Peer signature (EdDSA signature)
//----------------------------------------------------------------------

// PeerSignature is a EdDSA signature from the peer
type PeerSignature struct {
	Data []byte `size:"(Size)"`
}

// NewPeerSignature is a EdDSA signatre with the private peer key
func NewPeerSignature(data []byte) *PeerSignature {
	s := new(PeerSignature)
	size := s.Size()
	v := make([]byte, size)
	if len(data) > 0 {
		if uint(len(data)) < size {
			CopyAlignedBlock(v, data)
		} else {
			copy(v, data[:size])
		}
	}
	s.Data = v
	return s
}

// Size returns the length of the binary data
func (s *PeerSignature) Size() uint {
	return 64
}

// Bytes returns the binary representation of a peer signature.
func (s *PeerSignature) Bytes() []byte {
	return Clone(s.Data)
}
