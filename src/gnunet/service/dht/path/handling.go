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

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// Path handling
//----------------------------------------------------------------------

// path flags
const (
	PathTruncated = 1
	PathLastHop   = 2
)

// Path is the complete list of verified hops a message travelled.
// It also keeps the associated block hash and expiration time of
// the request for signature verification purposes.
type Path struct {
	Flags       uint32              `order:"big"`    // flags
	BlkHash     *crypto.HashCode    ``               // block hash value
	Expire      util.AbsoluteTime   ``               // expiration time
	TruncOrigin *util.PeerID        `opt:"(IsUsed)"` // truncated origin (optional)
	NumList     uint16              `order:"big"`    // number of list entries
	SplitPos    uint16              `order:"big"`    // optional split position
	List        []*Entry            `size:"NumList"` // list of path entries
	LastSig     *util.PeerSignature `opt:"(Isused)"` // last hop signature
	LastHop     *util.PeerID        `opt:"(IsUsed)"` // last hop peer id
}

// IsUsed checks if an optional field is used
func (p *Path) IsUsed(field string) bool {
	switch field {
	case "TruncOrigin":
		return p.Flags&PathTruncated != 0
	case "LastSig", "LastHop":
		return p.Flags&PathLastHop != 0
	}
	return false
}

// NewPath returns a new, empty path
func NewPath(bh *crypto.HashCode, expire util.AbsoluteTime) *Path {
	return &Path{
		Flags:       0,
		BlkHash:     bh,
		Expire:      expire,
		TruncOrigin: nil,
		NumList:     0,
		SplitPos:    0,
		List:        make([]*Entry, 0),
		LastSig:     nil,
		LastHop:     nil,
	}
}

// NewPathFromBytes reconstructs a path instance from binary data. The layout
// of the data must match with the layout used in Path.Bytes().
func NewPathFromBytes(buf []byte) (path *Path, err error) {
	if len(buf) == 0 {
		return
	}
	path = new(Path)
	err = data.Unmarshal(&path, buf)
	return
}

// Size of the binary representation (in message)
func (p *Path) Size() uint {
	var size uint
	if p.TruncOrigin != nil {
		size += p.TruncOrigin.Size()
	}
	size += uint(p.NumList) * p.List[0].Size()
	if p.LastSig != nil {
		size += p.LastSig.Size() + p.LastHop.Size()
	}
	return size
}

// Bytes returns a binary representation
func (p *Path) Bytes() []byte {
	buf, _ := data.Marshal(p)
	return buf
}

// Clone path instance
func (p *Path) Clone() *Path {
	return &Path{
		Flags:       p.Flags,
		BlkHash:     p.BlkHash,
		Expire:      p.Expire,
		TruncOrigin: p.TruncOrigin,
		NumList:     p.NumList,
		SplitPos:    p.SplitPos,
		List:        util.Clone(p.List),
		LastSig:     p.LastSig,
		LastHop:     p.LastHop,
	}
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
		p.NumList++
	}
	// update last hop signature
	p.LastSig = elem.Signature
	p.LastHop = elem.Signer
	p.Flags |= PathLastHop
}

// Verify path: process list entries from right to left (decreasing index).
// If an invalid signature is encountered, the path is truncated; only checked
// elements up to this point are included in the path (left trim).
// The method does not return a state; if the verification fails, the path is
// corrected (truncated or deleted) and would always verify OK.
func (p *Path) Verify(local *util.PeerID) {

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
		pe := p.NewElement(pred, p.LastHop, local)
		ok, err := pe.Verify(p.LastSig)
		if err != nil || !ok {
			// remove last hop signature and truncated origin; reset flags
			p.LastSig = nil
			p.LastHop = nil
			p.TruncOrigin = nil
			p.Flags = 0
		}
		return
	} else {
		// yes: process list of path elements
		signer := p.LastHop
		sig := p.LastSig
		succ := local
		num := len(p.List)
		var pred *util.PeerID
		for i := num - 1; i >= 0; i-- {
			if i == -1 {
				if p.TruncOrigin != nil {
					pred = p.TruncOrigin
				} else {
					pred = util.NewPeerID(nil)
				}
			} else {
				pred = p.List[i].Signer
			}
			pe := p.NewElement(pred, signer, succ)
			ok, err := pe.Verify(sig)
			if err != nil || !ok {
				// we need to truncate:
				logger.Printf(logger.WARN, "[path] Truncating path (invalid signature at hop %d)", i)

				// are we at the end of the list?
				if i == num-1 {
					// yes: the last hop signature failed -> reset path
					p.LastSig = nil
					p.LastHop = nil
					p.TruncOrigin = nil
					p.Flags = 0
					p.List = make([]*Entry, 0)
					return
				}
				// trim list
				p.Flags |= PathTruncated
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
			if i != -1 {
				sig = p.List[i].Signature
			}
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
	buf.WriteString(fmt.Sprintf("{to=%s, (%d)[", s, len(p.List)))
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
