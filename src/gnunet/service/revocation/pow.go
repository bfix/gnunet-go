// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
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
	"time"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/math"
	"golang.org/x/crypto/argon2"
)

//----------------------------------------------------------------------
// Proof-of-Work data
//----------------------------------------------------------------------

// PoWData is the proof-of-work data
type PoWData struct {
	PoW       uint64            `order:"big"` // start with this PoW value
	Timestamp util.AbsoluteTime // Timestamp of creation
	ZoneKey   []byte            `size:"32"` // public zone key to be revoked

	// transient attributes (not serialized)
	blob []byte // binary representation of serialized data
}

// NewPoWData creates a PoWData instance for the given arguments.
func NewPoWData(pow uint64, ts util.AbsoluteTime, zoneKey []byte) *PoWData {
	rd := &PoWData{
		PoW:       0,
		Timestamp: ts,
		ZoneKey:   zoneKey,
	}
	if rd.SetPoW(pow) != nil {
		return nil
	}
	return rd
}

func (p *PoWData) SetPoW(pow uint64) error {
	p.PoW = pow
	blob, err := data.Marshal(p)
	if err != nil {
		return err
	}
	p.blob = blob
	return nil
}

// GetPoW returns the last checked PoW value
func (p *PoWData) GetPoW() uint64 {
	if p.blob != nil {
		var val uint64
		binary.Read(bytes.NewReader(p.blob[:8]), binary.BigEndian, &val)
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
	key := argon2.Key(p.blob, []byte("gnunet-revocation-proof-of-work"), 3, 1024, 1, 64)
	return math.NewIntFromBytes(key)
}

//----------------------------------------------------------------------
// Revocation data
//----------------------------------------------------------------------

// RevData is the revocation data (wire format)
type RevData struct {
	Timestamp util.AbsoluteTime // Timestamp of creation
	PoWs      []uint64          `size:"32" order:"big"` // (Sorted) list of PoW values
	Signature []byte            `size:"64"`             // Signature (Proof-of-ownership).
	ZoneKey   []byte            `size:"32"`             // public zone key to be revoked
}

// SignedRevData is the block of data signed for a RevData instance.
type SignedRevData struct {
	Purpose   *crypto.SignaturePurpose
	ZoneKey   []byte            `size:"32"` // public zone key to be revoked
	Timestamp util.AbsoluteTime // Timestamp of creation
}

// NewRevData initializes a new RevData instance
func NewRevData(ts util.AbsoluteTime, pkey *ed25519.PublicKey) *RevData {
	rd := &RevData{
		Timestamp: ts,
		PoWs:      make([]uint64, 32),
		Signature: make([]byte, 64),
		ZoneKey:   make([]byte, 32),
	}
	copy(rd.ZoneKey, pkey.Bytes())
	return rd
}

// NewRevDataFromMsg initializes a new RevData instance from a GNUnet message
func NewRevDataFromMsg(m *message.RevocationRevokeMsg) *RevData {
	rd := &RevData{
		Timestamp: m.Timestamp,
		Signature: util.Clone(m.Signature),
		ZoneKey:   util.Clone(m.ZoneKey),
	}
	for i, pow := range m.PoWs {
		rd.PoWs[i] = pow
	}
	return rd
}

// Sign the revocation data
func (rd *RevData) Sign(skey *ed25519.PrivateKey) error {
	sigBlock := &SignedRevData{
		Purpose: &crypto.SignaturePurpose{
			Size:    48,
			Purpose: enums.SIG_REVOCATION,
		},
		ZoneKey:   rd.ZoneKey,
		Timestamp: rd.Timestamp,
	}
	sigData, err := data.Marshal(sigBlock)
	if err != nil {
		return err
	}
	sig, err := skey.EcSign(sigData)
	if err != nil {
		return err
	}
	copy(rd.Signature, sig.Bytes())
	return nil
}

// Verify a revocation object: returns the (smallest) number of leading
// zero-bits in the PoWs of this revocation; a number > 0, but smaller
// than the minimum (25) indicates invalid PoWs; a value of -1 indicates
// a failed signature; -2 indicates an expired revocation and -3 for a
// "out-of-order" PoW sequence.
func (rd *RevData) Verify(withSig bool) int {

	// (1) check signature
	if withSig {
		sigBlock := &SignedRevData{
			Purpose: &crypto.SignaturePurpose{
				Size:    48,
				Purpose: enums.SIG_REVOCATION,
			},
			ZoneKey:   rd.ZoneKey,
			Timestamp: rd.Timestamp,
		}
		sigData, err := data.Marshal(sigBlock)
		if err != nil {
			return -1
		}
		pkey := ed25519.NewPublicKeyFromBytes(rd.ZoneKey)
		sig, err := ed25519.NewEcSignatureFromBytes(rd.Signature)
		if err != nil {
			return -1
		}
		valid, err := pkey.EcVerify(sigData, sig)
		if err != nil || !valid {
			return -1
		}
	}

	// (2) check PoWs
	var (
		zbits int    = 512
		last  uint64 = 0
	)
	for _, pow := range rd.PoWs {
		// check sequence order
		if pow <= last {
			return -3
		}
		last = pow
		// compute number of leading zero-bits
		work := NewPoWData(pow, rd.Timestamp, rd.ZoneKey)
		lzb := 512 - work.Compute().BitLen()
		if lzb < zbits {
			zbits = lzb
		}
	}

	// (3) check expiration
	ttl := time.Duration((zbits-24)*365*24) * time.Hour
	if util.AbsoluteTimeNow().Add(ttl).Expired() {
		return -2
	}
	return zbits
}

// Compute tries to compute a valid Revocation; it returns the number of
// solved PoWs. The computation is complete if 32 PoWs have been found.
func (rd *RevData) Compute(ctx context.Context, bits int, last uint64) (int, uint64) {
	// set difficulty based on requested number of leading zero-bits
	difficulty := math.TWO.Pow(512 - bits).Sub(math.ONE)

	// initialize a new work record (single PoW computation)
	work := NewPoWData(0, rd.Timestamp, rd.ZoneKey)

	// work on all PoWs in a revocation data structure; make sure all PoWs
	// are set to a valid value (that results in a valid compute() result
	// below a given threshold)
	for i, pow := range rd.PoWs {
		// handle "new" pow value: set it to last_pow+1
		// this ensures a correctly sorted pow list by design.
		if pow == 0 && last != 0 {
			pow, last = last, 0
		}
		if pow == 0 && i > 0 {
			pow = rd.PoWs[i-1] + 1
		}
		// prepare for PoW_i
		work.SetPoW(pow)

		// Find PoW value in an (interruptable) loop
		out := make(chan bool)
		go func() {
			for {
				res := work.Compute()
				if res.Cmp(difficulty) < 0 {
					break
				}
				work.Next()
			}
			out <- true
		}()
	loop:
		for {
			select {
			case <-out:
				rd.PoWs[i] = work.GetPoW()
				break loop
			case <-ctx.Done():
				return i, work.GetPoW() + 1
			}
		}
	}
	// we have found all valid PoW values.
	return 32, 0
}

func (rd *RevData) Blob() []byte {
	blob, err := data.Marshal(rd)
	if err != nil {
		return nil
	}
	return blob
}
