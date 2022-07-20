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
	"gnunet/crypto"
	"gnunet/util"
)

//----------------------------------------------------------------------
// Path handling
//----------------------------------------------------------------------

// Path is the complete list of verified hops a message travelled.
// It also keeps the associated block hash and expiration time of
// the request for signature verification purposes.
type Path struct {
	BlkHash   *crypto.HashCode  // block hash value
	Expire    util.AbsoluteTime // expiration time
	List      []*Entry          // list of path entries
	Truncated bool              // truncated path?
}

// NewPath returns a new, empty path
func NewPath(bh *crypto.HashCode, expire util.AbsoluteTime) *Path {
	return &Path{
		BlkHash:   bh,
		Expire:    expire,
		List:      make([]*Entry, 0),
		Truncated: false,
	}
}

// Size of the binary representation (in message)
func (p *Path) Size() uint {
	pes := new(Entry).Size()
	pks := util.NewPeerID(nil).Size()
	sigs := util.NewPeerSignature(nil).Size()
	newSize := uint(len(p.List))*pes + sigs
	if p.Truncated {
		newSize += pks
	}
	return newSize
}

// Verify path: process list entries from right to left (decreasing index).
// If an invalid signature is encountered, the path is truncated; only checked
// elements up to this point are added to the resulting path (left trim).
// Returns a new path instance if truncated or the old instance otherwise.
func (p *Path) Verify(sender, local *util.PeerID) (newP *Path, trunc int) {
	newP = p
	trunc = -1
	vk := sender
	succ := local
	for i := len(p.List) - 1; i > 0; i-- {
		peWire := p.List[i]
		pred := peWire.Predecessor
		pe := NewElement(p.BlkHash, pred, succ, p.Expire)
		ok, err := pe.Verify(peWire.Signature)
		if err != nil || !ok {
			// we need to truncate: create new path
			newP = NewPath(p.BlkHash, p.Expire)
			newP.Truncated = true
			trunc = i
			num := (len(p.List) - 1) - i
			newP.List = make([]*Entry, num)
			if num > 0 {
				copy(newP.List, p.List[i+1:])
			}
			return
		}
		succ = vk
		vk = pred
	}
	return
}
