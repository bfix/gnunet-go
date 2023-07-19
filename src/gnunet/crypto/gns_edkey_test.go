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

package crypto

import (
	"bytes"
	"encoding/hex"
	"gnunet/enums"
	"gnunet/util"
	"testing"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/math"
)

func TestEdKeyCreate(t *testing.T) {
	// create private key
	zp, err := NewZonePrivate(enums.GNS_TYPE_EDKEY, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(zp.ID())
}

func TestDeriveEDKEY(t *testing.T) {
	// create new key pair
	zp, err := NewZonePrivate(enums.GNS_TYPE_EDKEY, nil)
	if err != nil {
		t.Fatal(err)
	}
	zk := zp.Public()

	// derive keys
	dzp, _, err := zp.Derive("@", "gns")
	if err != nil {
		t.Fatal(err)
	}
	dzk, _, err := zk.Derive("@", "gns")
	if err != nil {
		t.Fatal(err)
	}
	// check resuts
	if !bytes.Equal(dzp.Public().Bytes(), dzk.Bytes()) {
		t.Logf("dzp.Public = %s", hex.EncodeToString(dzp.Public().Bytes()))
		t.Logf("dzk = %s", hex.EncodeToString(dzk.Bytes()))
		t.Fatal("derive mismatch")
	}
}

// test 'DerivedSign' from LSD0001, 5.1.2. EDKEY
func TestDerivedSign(t *testing.T) {

	for i := 0; i < 20; i++ {
		// generate clamped private scalar and keys (EdDSA)
		a := util.NewRndArray(32)
		a[31] &= 248
		a[0] &= 127
		a[0] |= 64
		d := math.NewIntFromBytes(a)
		zp := ed25519.NewPrivateKeyFromD(d)
		zk := zp.Public()

		// calculate blinding factor
		h := math.NewIntRnd(ed25519N)

		// derive keys
		dzp := zp.Mult(h)
		dzk := zk.Mult(h)
		if !dzk.Q.Equals(dzp.Public().Q) {
			t.Fatal("derive")
		}

		// per draft:
		a1 := d.Rsh(3)
		a2 := h.Mul(a1).Mod(ed25519N)
		dd := a2.Lsh(3)
		dzp2 := ed25519.NewPrivateKeyFromD(dd)
		dzk2 := dzp2.Public()
		if !dzk.Q.Equals(dzk2.Q) {
			t.Fatal("mismatch")
		}
	}
}
