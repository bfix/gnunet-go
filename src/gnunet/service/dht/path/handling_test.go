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
	"testing"

	"github.com/bfix/gospel/crypto/ed25519"
)

type hop struct {
	peerid *util.PeerID
	seckey *ed25519.PrivateKey
}

func newHop() *hop {
	h := new(hop)
	var pk *ed25519.PublicKey
	pk, h.seckey = ed25519.NewKeypair()
	h.peerid = util.NewPeerID(pk.Bytes())
	return h
}

func sign(sd []byte, pk *ed25519.PrivateKey) (sig *util.PeerSignature, err error) {
	var s *ed25519.EdSignature
	if s, err = pk.EdSign(sd); err != nil {
		return
	}
	sig = util.NewPeerSignature(s.Bytes())
	return
}

func TestPath(t *testing.T) {

	// simulate a 'n' hop message path.
	n := 10 // number of hops
	f := 3  // failed hop signature
	hops := make([]*hop, n)
	for i := range hops {
		hops[i] = newHop()
	}

	// start with empty path
	pth := NewPath(crypto.NewHashCode(nil), util.AbsoluteTimeNever())
	//fmt.Println("Empty path: " + pth.String())

	// build path
	var err error
	pred := util.NewPeerID(nil)
	for i := 0; i < n-1; i++ {
		pe := pth.NewElement(pred, hops[i].peerid, hops[i+1].peerid)
		if pe.Signature, err = sign(pe.SignedData(), hops[i].seckey); err != nil {
			t.Fatal(err)
		}
		pth.Add(pe)
		//fmt.Printf("[%d] %s\n", i, pth.String())
		pred = hops[i].peerid
	}
	ps1 := pth.String()

	// verify path
	pth.Verify(hops[n-2].peerid, hops[n-1].peerid)
	ps2 := pth.String()
	if ps1 != ps2 {
		t.Fatal("path mismatch")
	}

	// invalidate signature
	pth.List[f].Signature = util.NewPeerSignature(nil)
	//fmt.Println(pth.String())

	// verify path again (must truncate)
	pth.Verify(hops[n-2].peerid, hops[n-1].peerid)
	ps3 := pth.String()
	//fmt.Println(ps3)

	// verify path again
	pth.Verify(hops[n-2].peerid, hops[n-1].peerid)
	ps4 := pth.String()
	if ps3 != ps4 {
		t.Fatal("truncated path mismatch")
	}
}
