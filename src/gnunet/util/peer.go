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

// PeerID is the 32-byte binary representation od a Ed25519 key
type PeerID struct {
	Key []byte `size:"32"`
}

// NewPeerID creates a new peer id from data.
func NewPeerID(data []byte) (p *PeerID) {
	p = &PeerID{
		Key: make([]byte, 32),
	}
	if data != nil {
		if len(data) < 32 {
			CopyAlignedBlock(p.Key, data)
		} else {
			copy(p.Key, data[:32])
		}
	}
	return
}

// Equals returns true if two peer IDs match.
func (p *PeerID) Equals(q *PeerID) bool {
	return bytes.Equal(p.Key, q.Key)
}

// String returns a human-readable representation of a peer id.
func (p *PeerID) String() string {
	return EncodeBinaryToString(p.Key)
}

func (p *PeerID) PublicKey() *ed25519.PublicKey {
	return ed25519.NewPublicKeyFromBytes(p.Key)
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

//----------------------------------------------------------------------

type PeerEphPublicKey struct {
	Data []byte `size:"32"` // Ed25519 public key
}

func NewPeerEphPublicKey(data []byte) *PeerEphPublicKey {
	var v []byte
	if data == nil {
		v = make([]byte, 64)
	} else {
		v = Clone(data)
	}
	return &PeerEphPublicKey{
		Data: v,
	}
}
