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

package crypto

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/math"
)

var (
	d_1 = []byte{
		0x7F, 0xDE, 0x7A, 0xAA, 0xEA, 0x0D, 0xA1, 0x7A,
		0x7B, 0xCB, 0x4F, 0x57, 0x49, 0xCC, 0xA9, 0xBE,
		0xA7, 0xFB, 0x2B, 0x85, 0x77, 0xAD, 0xC9, 0x55,
		0xDA, 0xB2, 0x68, 0xB2, 0xB4, 0xCC, 0x24, 0x78,
	}

	d_2 = []byte{
		0x20, 0x3f, 0x2f, 0x8c, 0x54, 0xf4, 0x1a, 0xd3,
		0x01, 0x9a, 0x56, 0x92, 0x19, 0xda, 0xee, 0x4f,
		0xd2, 0x53, 0x55, 0xa6, 0x3c, 0xfc, 0x57, 0x40,
		0x8a, 0xb0, 0x86, 0x88, 0xf6, 0x86, 0xf4, 0x9c,
	}

	ss = []byte{
		0x0a, 0x49, 0x6e, 0x6b, 0x83, 0xca, 0x14, 0xeb,
		0xa5, 0x0f, 0x45, 0x49, 0x1d, 0x90, 0x7e, 0x0c,
		0x07, 0x56, 0x90, 0x16, 0xb2, 0x43, 0x7a, 0x0e,
		0x91, 0x1f, 0x73, 0xe3, 0x4f, 0xbf, 0xfd, 0x85,
		0x55, 0x86, 0x02, 0xc7, 0x42, 0xc0, 0x29, 0xb0,
		0x70, 0xe3, 0xee, 0xad, 0x41, 0x89, 0xb6, 0xc1,
		0x44, 0x71, 0xde, 0x2b, 0x60, 0x4e, 0x7b, 0x75,
		0x05, 0xbd, 0x1b, 0x85, 0xd5, 0xfd, 0x63, 0x60,
	}

	prv_1, prv_2 *ed25519.PrivateKey
	pub_1, pub_2 *ed25519.PublicKey
	ss_1, ss_2   []byte
)

func calcSharedSecret() bool {
	calc := func(prv *ed25519.PrivateKey, pub *ed25519.PublicKey) []byte {
		x := sha512.Sum512(pub.Mult(prv.D).Q.X().Bytes())
		return x[:]
	}
	// compute shared secret
	ss_1 = calc(prv_1, pub_2)
	ss_2 = calc(prv_2, pub_1)
	return bytes.Compare(ss_1, ss_2) == 0
}

func TestDHE(t *testing.T) {
	// generate two key pairs
	prv_1 = ed25519.NewPrivateKeyFromD(math.NewIntFromBytes(d_1))
	pub_1 = prv_1.Public()
	prv_2 = ed25519.NewPrivateKeyFromD(math.NewIntFromBytes(d_2))
	pub_2 = prv_2.Public()

	if !calcSharedSecret() {
		t.Fatal("Shared secret mismatch")
	}
	if testing.Verbose() {
		t.Logf("SS_1 = %s\n", hex.EncodeToString(ss_1))
		t.Logf("SS_2 = %s\n", hex.EncodeToString(ss_2))
	}

	if bytes.Compare(ss_1[:], ss) != 0 {
		t.Logf("SS(expected) = %s\n", hex.EncodeToString(ss))
		t.Logf("SS(computed) = %s\n", hex.EncodeToString(ss_1[:]))
		t.Fatal("Wrong shared secret:")
	}

}

func TestDHERandom(t *testing.T) {
	failed := 0
	once := false
	for i := 0; i < 100; i++ {
		prv_1 = ed25519.NewPrivateKeyFromD(math.NewIntRnd(ED25519_N))
		pub_1 = prv_1.Public()
		prv_2 = ed25519.NewPrivateKeyFromD(math.NewIntRnd(ED25519_N))
		pub_2 = prv_2.Public()

		if !calcSharedSecret() {
			if !once {
				once = true
				t.Logf("d1=%s\n", hex.EncodeToString(prv_1.D.Bytes()))
				t.Logf("d2=%s\n", hex.EncodeToString(prv_2.D.Bytes()))
				t.Logf("ss1=%s\n", hex.EncodeToString(ss_1))
				t.Logf("ss2=%s\n", hex.EncodeToString(ss_2))
				dd := prv_1.D.Mul(prv_2.D).Mod(ED25519_N)
				pk := sha512.Sum512(ed25519.NewPrivateKeyFromD(dd).Public().Q.X().Bytes())
				t.Logf("ss0=%s\n", hex.EncodeToString(pk[:]))
			}
			failed++
		}
	}
	if failed > 0 {
		t.Fatalf("Shared secret mismatches: %d/1000", failed)
	}
}
