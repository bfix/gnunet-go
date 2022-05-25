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

import "bytes"

// PeerID is the 32-byte binary representation od a Ed25519 key
type PeerID struct {
	Key []byte `size:"32"`
}

// NewPeerID creates a new object from the data.
func NewPeerID(data []byte) *PeerID {
	if data == nil {
		data = make([]byte, 32)
	} else {
		size := len(data)
		if size > 32 {
			data = data[:32]
		} else if size < 32 {
			buf := make([]byte, 32)
			CopyAlignedBlock(buf, data)
			data = buf
		}
	}
	return &PeerID{
		Key: data,
	}
}

// Equals returns true if two peer IDs match.
func (p *PeerID) Equals(q *PeerID) bool {
	return bytes.Equal(p.Key, q.Key)
}

// String returns a human-readable representation of a peer id.
func (p *PeerID) String() string {
	return EncodeBinaryToString(p.Key)
}
