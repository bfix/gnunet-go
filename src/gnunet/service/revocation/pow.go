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

package revocation

import (
	"bytes"
	"context"
	"encoding/binary"
	"sort"
	"time"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/math"
	"golang.org/x/crypto/argon2"
)

//----------------------------------------------------------------------
// Proof-of-Work data
//----------------------------------------------------------------------

const (
	// MinDifficulty for revocations -> expires in ~1year
	MinDifficulty = 23
)

// PoWData is the proof-of-work data
type PoWData struct {
	PoW       uint64            `order:"big"` // start with this PoW value
	Timestamp util.AbsoluteTime ``            // Timestamp of creation
	ZoneKey   *crypto.ZoneKey   ``            // public zone key to be revoked

	// transient attributes (not serialized)
	blob []byte // binary representation of serialized data
}

// NewPoWData creates a PoWData instance for the given arguments.
func NewPoWData(pow uint64, ts util.AbsoluteTime, zoneKey *crypto.ZoneKey) *PoWData {
	rd := &PoWData{
		PoW:       0,
		Timestamp: ts,
		ZoneKey:   zoneKey,
	}
	rd.SetPoW(pow)
	return rd
}

// SetPoW sets a new PoW value in the data structure
func (p *PoWData) SetPoW(pow uint64) {
	p.PoW = pow
	p.blob = p.Blob()
}

// GetPoW returns the last checked PoW value
func (p *PoWData) GetPoW() uint64 {
	if p.blob != nil {
		var val uint64
		_ = binary.Read(bytes.NewReader(p.blob[:8]), binary.BigEndian, &val)
		p.PoW = val
	}
	return p.PoW
}

// Next selects the next PoW to be tested.
func (p *PoWData) Next() {
	var incr func(pos int)
	incr = func(pos int) {
		p.blob[pos]++
		if p.blob[pos] != 0 || pos == 0 {
			return
		}
		incr(pos - 1)
	}
	incr(7)
}

// Compute calculates the current result for a PoWData content.
// The result is returned as a big integer value.
func (p *PoWData) Compute() *math.Int {
	key := argon2.IDKey(p.blob, []byte("GnsRevocationPow"), 3, 1024, 1, 64)
	return math.NewIntFromBytes(key)
}

// Blob returns a serialized instance of the work unit
func (p *PoWData) Blob() []byte {
	blob, err := data.Marshal(p)
	if err != nil {
		return nil
	}
	return blob
}

//----------------------------------------------------------------------
// Revocation data
//----------------------------------------------------------------------

// RevData is the revocation data (wire format)
type RevData struct {
	Timestamp  util.AbsoluteTime     ``                      // Timestamp of creation
	TTL        util.RelativeTime     ``                      // TTL of revocation
	PoWs       []uint64              `size:"32" order:"big"` // (Sorted) list of PoW values
	ZoneKeySig *crypto.ZoneSignature ``                      // public zone key to be revoked
}

// SignedRevData is the block of data signed for a RevData instance.
type SignedRevData struct {
	Purpose   *crypto.SignaturePurpose // signature purpose
	Timestamp util.AbsoluteTime        // Timestamp of creation
	ZoneKey   *crypto.ZoneKey          // public zone key to be revoked
}

// NewRevDataFromMsg initializes a new RevData instance from a GNUnet message
func NewRevDataFromMsg(m *message.RevocationRevokeMsg) *RevData {
	return &RevData{
		Timestamp:  m.Timestamp,
		ZoneKeySig: m.ZoneKeySig,
		PoWs:       util.Clone(m.PoWs),
	}
}

// Size of a serialized RevData object.
func (rd *RevData) Size() int {
	return 16 + 8*len(rd.PoWs) + int(rd.ZoneKeySig.SigSize())
}

// Sign the revocation data
func (rd *RevData) Sign(skey *crypto.ZonePrivate) (err error) {
	sigBlock := &SignedRevData{
		Purpose: &crypto.SignaturePurpose{
			Size:    uint32(20 + rd.ZoneKeySig.KeySize()),
			Purpose: enums.SIG_REVOCATION,
		},
		Timestamp: rd.Timestamp,
		ZoneKey:   &rd.ZoneKeySig.ZoneKey,
	}
	sigData, err := data.Marshal(sigBlock)
	if err == nil {
		rd.ZoneKeySig, err = skey.Sign(sigData)
	}
	return
}

// Verify a revocation object and return the average difficulty of the PoWs
// in this revocation and a verification status (-1=failed signature, -2=
// expired revocation, -3="out-of-order" PoW sequence).
func (rd *RevData) Verify(withSig bool) (zbits float64, rc int) {
	// (1) check signature
	if withSig {
		sigBlock := &SignedRevData{
			Purpose: &crypto.SignaturePurpose{
				Size:    uint32(20 + rd.ZoneKeySig.KeySize()),
				Purpose: enums.SIG_REVOCATION,
			},
			Timestamp: rd.Timestamp,
			ZoneKey:   &rd.ZoneKeySig.ZoneKey,
		}
		sigData, err := data.Marshal(sigBlock)
		if err != nil {
			return 0., -1
		}
		valid, err := rd.ZoneKeySig.Verify(sigData)
		if err != nil || !valid {
			return 0., -1
		}
	}

	// (2) check PoWs
	var last uint64
	for _, pow := range rd.PoWs {
		// check sequence order
		if pow <= last {
			return 0., -3
		}
		last = pow
		// compute number of leading zero-bits
		work := NewPoWData(pow, rd.Timestamp, &rd.ZoneKeySig.ZoneKey)
		zbits += float64(512 - work.Compute().BitLen())
	}
	zbits /= float64(len(rd.PoWs))

	// (3) check expiration
	if zbits >= 23.0 {
		ttl := time.Duration(int((zbits-22)*365*24*1.1)) * time.Hour
		if util.AbsoluteTimeNow().Add(ttl).Expired() {
			return zbits, -2
		}
	}
	return zbits, 0
}

//----------------------------------------------------------------------
// RevData structure for computation
//----------------------------------------------------------------------

// RevDataCalc is the revocation data structure used while computing
// the revocation data object.
type RevDataCalc struct {
	RevData
	Bits        []uint16 `size:"32" order:"big"` // number of leading zeros
	SmallestIdx byte     // index of smallest number of leading zeros
}

// NewRevDataCalc initializes a new RevDataCalc instance
func NewRevDataCalc(zkey *crypto.ZoneKey) *RevDataCalc {
	rd := &RevDataCalc{
		RevData: RevData{
			Timestamp:  util.AbsoluteTimeNow(),
			PoWs:       make([]uint64, 32),
			ZoneKeySig: nil,
		},
		Bits:        make([]uint16, 32),
		SmallestIdx: 0,
	}
	return rd
}

// Size of a serialized RevData object.
func (rdc *RevDataCalc) Size() int {
	return rdc.RevData.Size() + 2*len(rdc.Bits) + 1
}

// Average number of leading zero-bits in current list
func (rdc *RevDataCalc) Average() float64 {
	var sum uint16
	for _, num := range rdc.Bits {
		sum += num
	}
	return float64(sum) / 32.
}

// Insert a PoW that is "better than the worst" current PoW element.
func (rdc *RevDataCalc) Insert(pow uint64, bits uint16) (float64, uint16) {
	if bits > rdc.Bits[rdc.SmallestIdx] {
		rdc.PoWs[rdc.SmallestIdx] = pow
		rdc.Bits[rdc.SmallestIdx] = bits
		rdc.sortBits()
	}
	return rdc.Average(), rdc.Bits[rdc.SmallestIdx]
}

// Get the smallest bit position
func (rdc *RevDataCalc) sortBits() {
	var (
		min uint16 = 512
		pos        = 0
	)
	for i, bits := range rdc.Bits {
		if bits < min {
			min = bits
			pos = i
		}
	}
	rdc.SmallestIdx = byte(pos)
}

// Compute tries to compute a valid Revocation; it returns the average number
// of leading zero-bits and the last PoW value tried. The computation is
// complete if the average above is greater or equal to 'bits'.
func (rdc *RevDataCalc) Compute(ctx context.Context, bits int, last uint64, cb func(float64, uint64)) (float64, uint64) {
	// find the largest PoW value in current work unit
	work := NewPoWData(0, rdc.Timestamp, &rdc.ZoneKeySig.ZoneKey)
	var max uint64
	for i, pow := range rdc.PoWs {
		if pow == 0 {
			max++
			work.SetPoW(max)
			res := work.Compute()
			rdc.Bits[i] = uint16(512 - res.BitLen())
		} else if pow > max {
			max = pow
		}
	}
	// adjust 'last' value
	if last <= max {
		last = max + 1
	}

	// Find PoW value in an (interruptable) loop
	out := make(chan bool)
	go func() {
		work.SetPoW(last + 1)
		smallest := rdc.Bits[rdc.SmallestIdx]
		average := rdc.Average()
		for average < float64(bits) {
			res := work.Compute()
			num := uint16(512 - res.BitLen())
			if num > smallest {
				pow := work.GetPoW()
				average, smallest = rdc.Insert(pow, num)
				cb(average, pow)
			}
			work.Next()
		}
		out <- true
	}()
loop:
	for {
		select {
		case <-out:
			break loop
		case <-ctx.Done():
			break loop
		}
	}
	// re-order the PoWs for compliance
	sort.Slice(rdc.PoWs, func(i, j int) bool { return rdc.PoWs[i] < rdc.PoWs[j] })
	for i, pow := range rdc.PoWs {
		work.SetPoW(pow)
		rdc.Bits[i] = uint16(512 - work.Compute().BitLen())
	}
	rdc.sortBits()
	return rdc.Average(), work.GetPoW()
}

// Blob returns the binary data structure (wire format).
func (rdc *RevDataCalc) Blob() []byte {
	blob, err := data.Marshal(rdc)
	if err != nil {
		return nil
	}
	return blob
}
