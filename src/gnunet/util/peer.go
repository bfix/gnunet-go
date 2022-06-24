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
)

//----------------------------------------------------------------------
// Peer public key (Ed25519 public key)
//----------------------------------------------------------------------

// PeerPublicKey is the binary representation of an Ed25519 public key
type PeerPublicKey struct {
	Data []byte `size:"32"` // Ed25519 public key data
}

// NewPeerPublicKey creates a key instance from binary data
func NewPeerPublicKey(data []byte) *PeerPublicKey {
	pk := &PeerPublicKey{
		Data: make([]byte, 32),
	}
	if data != nil {
		if len(data) < 32 {
			CopyAlignedBlock(pk.Data, data)
		} else {
			copy(pk.Data, data[:32])
		}
	}
	return pk
}

//----------------------------------------------------------------------
// Peer identifier:
//----------------------------------------------------------------------

// PeerID is a wrpped PeerPublicKey
type PeerID PeerPublicKey

// NewPeerID creates a new peer id from data.
func NewPeerID(data []byte) (p *PeerID) {
	return (*PeerID)(NewPeerPublicKey(data))
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

// PeerSignature is a EdDSA signature from the peer
type PeerSignature struct {
	Data []byte `size:"64"`
}

// NewPeerSignature is a EdDSA signatre with the private peer key
func NewPeerSignature(data []byte) *PeerSignature {
	var v []byte
	if data == nil {
		v = make([]byte, 64)
	} else {
		v = Clone(data)
	}
	return &PeerSignature{
		Data: v,
	}
}
