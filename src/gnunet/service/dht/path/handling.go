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
	"bytes"
	"encoding/hex"
	"fmt"
	"gnunet/crypto"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// Path handling
//----------------------------------------------------------------------

// Path is the complete list of verified hops a message travelled.
// It also keeps the associated block hash and expiration time of
// the request for signature verification purposes.
type Path struct {
	BlkHash     *crypto.HashCode    // block hash value
	Expire      util.AbsoluteTime   // expiration time
	TruncOrigin *util.PeerID        // truncated origin (optional)
	List        []*Entry            // list of path entries
	LastSig     *util.PeerSignature // last hop signature
}

// NewPath returns a new, empty path
func NewPath(bh *crypto.HashCode, expire util.AbsoluteTime) *Path {
	return &Path{
		BlkHash:     bh,
		Expire:      expire,
		TruncOrigin: nil,
		List:        make([]*Entry, 0),
		LastSig:     nil,
	}
}

// Size of the binary representation (in message)
func (p *Path) Size() uint {
	var size uint
	if p.TruncOrigin != nil {
		size += p.TruncOrigin.Size()
	}
	if num := uint(len(p.List)); num > 0 {
		size += num * p.List[0].Size()
	}
	if p.LastSig != nil {
		size += p.LastSig.Size()
	}
	return size
}

// NewElement creates a new path element from data
func (p *Path) NewElement(pred, signer, succ *util.PeerID) *Element {
	return &Element{
		elementData: elementData{
			Expiration:      p.Expire,
			BlockHash:       p.BlkHash,
			PeerPredecessor: pred,
			PeerSuccessor:   succ,
		},
		Entry: Entry{
			Signer:    signer,
			Signature: nil,
		},
	}
}

// Add new path element with signature (append to path)
func (p *Path) Add(elem *Element) {
	// append path element if we have a last hop signature
	if p.LastSig != nil {
		e := &Entry{
			Signer:    elem.PeerPredecessor,
			Signature: p.LastSig,
		}
		p.List = append(p.List, e)
	}
	// update last hop signature
	p.LastSig = elem.Signature
}

// Verify path: process list entries from right to left (decreasing index).
// If an invalid signature is encountered, the path is truncated; only checked
// elements up to this point are included in the path (left trim).
// The method does not return a state; if the verification fails, the path is
// corrected (truncated or deleted) and would always verify OK.
func (p *Path) Verify(sender, local *util.PeerID) {

	// do we have path elements?
	if len(p.List) == 0 {
		// no elements: last hop signature available?
		if p.LastSig == nil {
			// no: nothing to verify
			return
		}
		// get predecessor (either 0 or truncated origins)
		pred := util.NewPeerID(nil)
		if p.TruncOrigin != nil {
			pred = p.TruncOrigin
		}
		// check last hop signature
		pe := p.NewElement(pred, sender, local)
		ok, err := pe.Verify(p.LastSig)
		if err != nil || !ok {
			// remove last hop signature (and truncated origin)
			p.LastSig = nil
			p.TruncOrigin = nil
		}
		return
	} else {
		// yes: process list of path elements
		signer := sender
		sig := p.LastSig
		succ := local
		num := len(p.List)
		for i := num - 1; i > 0; i-- {
			peWire := p.List[i]
			pred := peWire.Signer
			pe := p.NewElement(pred, signer, succ)
			ok, err := pe.Verify(sig)
			if err != nil || !ok {
				// we need to truncate:
				logger.Printf(logger.WARN, "[path] Truncating path (invalid signature at hop %d)", i)

				// are we at the end of the list?
				if i == num-1 {
					// yes: the last hop signature failed -> reset path
					p.LastSig = nil
					p.TruncOrigin = nil
					p.List = make([]*Entry, 0)
					return
				}
				// trim list
				p.TruncOrigin = signer
				size := num - 2 - i
				list := make([]*Entry, size)
				if size > 0 {
					copy(list, p.List[i+2:])
				}
				p.List = list
				return
			}
			// check next path element
			succ = signer
			signer = pred
			sig = peWire.Signature
		}
	}
}

// String returs a uman-readbale representation
func (p *Path) String() string {
	buf := new(bytes.Buffer)
	s := "0"
	if p.TruncOrigin != nil {
		s = p.TruncOrigin.String()
	}
	buf.WriteString(fmt.Sprintf("{ to=%s, (%d)[", s, len(p.List)))
	for _, e := range p.List {
		buf.WriteString(e.String())
	}
	s = "0"
	if p.LastSig != nil {
		s = hex.EncodeToString(p.LastSig.Bytes())
	}
	num := len(s)
	if num > 16 {
		s = s[:8] + ".." + s[num-8:]
	}
	buf.WriteString(fmt.Sprintf("], ls=%s}", s))
	return buf.String()
}
