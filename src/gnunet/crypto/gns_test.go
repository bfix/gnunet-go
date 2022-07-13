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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"gnunet/util"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

func TestDeriveBlockKey(t *testing.T) {
	var (
		PUB = []byte{
			0x23, 0xd8, 0x9a, 0x29, 0xda, 0x0f, 0x68, 0x08,
			0xc6, 0xb6, 0xd5, 0xe5, 0x9c, 0xdd, 0x6a, 0x6f,
			0xcf, 0x3e, 0x2b, 0xb0, 0x06, 0xf4, 0x66, 0xd5,
			0x42, 0x3a, 0x93, 0x5d, 0x6b, 0x4d, 0x7e, 0x10,
		}
		LABEL  = "home"
		EXPIRE = util.NewAbsoluteTime(time.Unix(1643714700060589, 0))
		SKEY   = []byte{
			0x0c, 0xf7, 0x4d, 0x44, 0x19, 0xe4, 0xac, 0x52,
			0x3d, 0x14, 0xf4, 0x9b, 0x09, 0x6c, 0x52, 0xb6,
			0xb3, 0xf5, 0x06, 0x68, 0x98, 0x26, 0xa5, 0xea,
			0x06, 0x93, 0xfd, 0x4d, 0x80, 0xab, 0xf0, 0x44,
		}
		IV = []byte{
			0x04, 0x41, 0xfc, 0xfc,
			0x1b, 0x1f, 0xb2, 0xee, 0x6f, 0x27, 0x85, 0x40,
			0x00, 0x00, 0x00, 0x01,
		}
	)

	// create and initialize new public zone key (PKEY)
	zkey := new(PKEYPublicImpl)
	if err := zkey.Init(PUB); err != nil {
		t.Fatal(err)
	}

	// derive and check a key for symmetric cipher
	skey := zkey.BlockKey(LABEL, EXPIRE)
	if !bytes.Equal(IV, skey[32:]) {
		t.Logf("AES_IV(computed) = %s\n", hex.EncodeToString(skey[32:]))
		t.Logf("AES_IV(expected) = %s\n", hex.EncodeToString(IV))
		t.Fatal("AES IV mismatch")
	}
	if !bytes.Equal(SKEY, skey[:32]) {
		t.Logf("AES_KEY(computed) = %s\n", hex.EncodeToString(skey[:32]))
		t.Logf("AES_KEY(expected) = %s\n", hex.EncodeToString(SKEY))
		t.Fatal("AES KEY mismatch")
	}
}

func TestDecryptBlock(t *testing.T) {
	var (
		DATA = []byte{
			0x00, 0x00, 0x00, 0x02, 0x00, 0x34, 0xe5, 0x3b,
			0xe1, 0x93, 0x79, 0x91, 0x00, 0x00, 0x00, 0x04,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x02, 0x03, 0x04, 0x00, 0x5c, 0xe4, 0xa5,
			0x39, 0x4a, 0xd9, 0x91, 0x00, 0x00, 0x00, 0x24,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			0x00, 0x01, 0x00, 0x00, 0x0e, 0x60, 0x1b, 0xe4,
			0x2e, 0xb5, 0x7f, 0xb4, 0x69, 0x76, 0x10, 0xcf,
			0x3a, 0x3b, 0x18, 0x34, 0x7b, 0x65, 0xa3, 0x3f,
			0x02, 0x5b, 0x5b, 0x17, 0x4a, 0xbe, 0xfb, 0x30,
			0x80, 0x7b, 0xfe, 0xcf, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}
		OUT = []byte{
			0x00, 0xe4, 0x83, 0x7e, 0xb5, 0xd0, 0x4f, 0x92,
			0x90, 0x3d, 0xe4, 0xb5, 0x23, 0x4e, 0x8c, 0xca,
			0xc5, 0x73, 0x6c, 0x97, 0x93, 0x37, 0x9a, 0x59,
			0xc3, 0x33, 0x75, 0xfc, 0x89, 0x51, 0xac, 0xa2,
			0xeb, 0x7a, 0xad, 0x06, 0x7b, 0xf9, 0xaf, 0x60,
			0xbf, 0x26, 0x75, 0x86, 0x46, 0xa1, 0x7f, 0x5e,
			0x5c, 0x3b, 0x62, 0x15, 0xf9, 0x40, 0x79, 0x54,
			0x5b, 0x1c, 0x4d, 0x4f, 0x1b, 0x2e, 0xbb, 0x22,
			0xc2, 0xb4, 0xda, 0xd4, 0x41, 0x26, 0x81, 0x7b,
			0x6f, 0x00, 0x15, 0x30, 0xd4, 0x76, 0x40, 0x1d,
			0xd6, 0x7a, 0xc0, 0x14, 0x85, 0x54, 0xe8, 0x06,
			0x35, 0x3d, 0xa9, 0xe4, 0x29, 0x80, 0x79, 0xf3,
			0xe1, 0xb1, 0x69, 0x42, 0xc4, 0x8d, 0x90, 0xc4,
			0x36, 0x0c, 0x61, 0x23, 0x8c, 0x40, 0xd9, 0xd5,
			0x29, 0x11, 0xae, 0xa5, 0x2c, 0xc0, 0x03, 0x7a,
			0xc7, 0x16, 0x0b, 0xb3, 0xcf, 0x5b, 0x2f, 0x4a,
			0x72, 0x2f, 0xd9, 0x6b,
		}
		LABEL  = "test"
		EXPIRE = util.AbsoluteTime{
			Val: uint64(14888744139323793),
		}
		PUB = []byte{
			// zone type
			0x00, 0x01, 0x00, 0x00,

			// public key
			0x67, 0x7c, 0x47, 0x7d, 0x2d, 0x93, 0x09, 0x7c,
			0x85, 0xb1, 0x95, 0xc6, 0xf9, 0x6d, 0x84, 0xff,
			0x61, 0xf5, 0x98, 0x2c, 0x2c, 0x4f, 0xe0, 0x2d,
			0x5a, 0x11, 0xfe, 0xdf, 0xb0, 0xc2, 0x90, 0x1f,
		}
	)

	// create and initialize new public zone key (PKEY)
	zkey, err := NewZoneKey(PUB)
	if err != nil {
		t.Fatal(err)
	}

	out, err := zkey.Encrypt(DATA, LABEL, EXPIRE)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, OUT) {
		t.Logf("Decrypt(computed) = %s\n", hex.EncodeToString(out))
		t.Logf("Decrypt(expected) = %s\n", hex.EncodeToString(OUT))
		t.Fatal("Decryptions failed")
	}
}

func TestVerifyBlock(t *testing.T) {
	var (
		SIGNED = []byte{
			0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x0f,
			0x00, 0x05, 0xad, 0x0e, 0x60, 0x28, 0xfe, 0x80,
			0xac, 0xa5, 0x3c, 0x55, 0x63, 0x21, 0x31, 0x1f,
			0x11, 0x6e, 0xef, 0x48, 0xed, 0x53, 0x46, 0x31,
			0x7c, 0x50, 0xfb, 0x6b, 0xa6, 0xc8, 0x6c, 0x46,
			0x1e, 0xe3, 0xca, 0x45, 0xcd, 0x5b, 0xd6, 0x86,
			0x42, 0x87, 0xef, 0x18, 0xce, 0x8e, 0x83, 0x21,
			0x04, 0xcb, 0xcf, 0x40, 0x7e, 0x0f, 0x51, 0x54,
			0xe2, 0x3c, 0xde, 0xe9, 0x22, 0x00, 0xff, 0x40,
			0xbb, 0x53, 0xe3, 0x69, 0x99, 0x92, 0x47, 0x97,
			0xf0, 0x4e, 0x3b, 0x70,
		}
		SIG = []byte{
			// zone type
			0x00, 0x01, 0x00, 0x00,

			// public key
			0x26, 0x84, 0x1b, 0x24, 0x35, 0xa4, 0x63, 0xe9,
			0xf0, 0x48, 0xae, 0x3e, 0xf7, 0xe8, 0x1b, 0xca,
			0x55, 0x9f, 0x4c, 0x1e, 0x16, 0x18, 0xa6, 0xd3,
			0x5b, 0x91, 0x0d, 0x54, 0x31, 0x6e, 0xbf, 0x97,

			// signature
			0x09, 0xc9, 0x6a, 0xda, 0x69, 0xce, 0x7c, 0x91,
			0xbd, 0xa4, 0x59, 0xdc, 0xc9, 0x76, 0xf4, 0x6c,
			0x62, 0xb7, 0x79, 0x3f, 0x94, 0xb2, 0xf6, 0xf0,
			0x90, 0x17, 0x4e, 0x2f, 0x68, 0x49, 0xf8, 0xcc,
			0x0b, 0x77, 0x32, 0x32, 0x28, 0x77, 0x2d, 0x2a,
			0x31, 0x31, 0xc1, 0x2c, 0x44, 0x18, 0xf2, 0x5f,
			0x1a, 0xe9, 0x8b, 0x2e, 0x65, 0xca, 0x1d, 0xe8,
			0x22, 0x82, 0x6a, 0x06, 0xe0, 0x6a, 0x5a, 0xe5,
		}
	)

	// instantiate and initialize signature
	sig, err := NewZoneSignature(SIG)
	if err != nil {
		t.Fatal(err)
	}
	// verify signature
	ok, err := sig.Verify(SIGNED)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature verify failed")
	}
}

func TestDeriveH(t *testing.T) {
	var (
		D = []byte{
			// private scalar (big-endian)
			0x74, 0x50, 0xf7, 0x1d, 0xef, 0x64, 0x11, 0xe0,
			0xab, 0x0e, 0x6a, 0x1d, 0xfd, 0x1d, 0x9c, 0xcd,
			0x0e, 0xaf, 0x71, 0x95, 0x24, 0x94, 0xcc, 0xf5,
			0x1b, 0x85, 0xff, 0xac, 0x5d, 0xb0, 0x93, 0xc8,
		}
		PUB = []byte{
			// zone type
			0x00, 0x01, 0x00, 0x00,
			// public key data
			0x23, 0xd8, 0x9a, 0x29, 0xda, 0x0f, 0x68, 0x08,
			0xc6, 0xb6, 0xd5, 0xe5, 0x9c, 0xdd, 0x6a, 0x6f,
			0xcf, 0x3e, 0x2b, 0xb0, 0x06, 0xf4, 0x66, 0xd5,
			0x42, 0x3a, 0x93, 0x5d, 0x6b, 0x4d, 0x7e, 0x10,
		}

		ID      = "000G0013V2D2KPGFD04CDDPNWPEDTTKFSWZ2QC06YHKDAGHTJDEPPKBY20"
		LABEL   = "home"
		CONTEXT = "gns"

		H = []byte{
			0x07, 0x1e, 0xfc, 0xa7, 0xdb, 0x28, 0x50, 0xbd,
			0x6f, 0x35, 0x4e, 0xbf, 0xe3, 0x8c, 0x5b, 0xbf,
			0xd6, 0xba, 0x2f, 0x80, 0x5c, 0xd8, 0xd3, 0xb5,
			0x4e, 0xdd, 0x7f, 0x3d, 0xd0, 0x73, 0x0d, 0x1a,
		}
		Q = []byte{
			// zone type
			0x00, 0x01, 0x00, 0x00,
			// derived public key data
			0x9f, 0x27, 0xad, 0x25, 0xb5, 0x95, 0x4a, 0x46,
			0x7b, 0xc6, 0x5a, 0x67, 0x6b, 0x7a, 0x6d, 0x23,
			0xb2, 0xef, 0x30, 0x0f, 0x7f, 0xc7, 0x00, 0x58,
			0x05, 0x9e, 0x7f, 0x29, 0xe5, 0x94, 0xb5, 0xc1,
		}
		QUERY = []byte{
			0xa9, 0x1a, 0x2c, 0x46, 0xf1, 0x98, 0x35, 0x50,
			0x4f, 0x4e, 0x96, 0x78, 0x2d, 0x77, 0xd1, 0x3b,
			0x9d, 0x4e, 0x61, 0xf3, 0x50, 0xe2, 0xe6, 0xa5,
			0xc2, 0xd1, 0x36, 0xc1, 0xf1, 0x37, 0x94, 0x79,
			0x19, 0xe9, 0xab, 0x2b, 0xae, 0xb5, 0xb9, 0x79,
			0xe9, 0x1e, 0xf2, 0x6a, 0xaa, 0x54, 0x81, 0x65,
			0xac, 0xb2, 0xec, 0xca, 0x8e, 0x30, 0x76, 0x1c,
			0xc2, 0x1b, 0xbe, 0x89, 0x0b, 0x34, 0x6d, 0xa1,
		}
	)

	// create private key from scalar
	prv, err := NewZonePrivate(ZONE_PKEY, D)
	if err != nil {
		t.Fatal(err)
	}

	// derive and checkpublic key
	pub := prv.Public()
	if !bytes.Equal(pub.Bytes(), PUB) {
		t.Fatal("wrong public key")
	}

	// test ID
	id := pub.ID()
	if ID != id {
		t.Logf("id = %s\n", id)
		t.Logf("ID = %s\n", ID)
		t.Fatal("wrong ID")
	}

	// test key derivation
	dpub, h, err := pub.Derive(LABEL, CONTEXT)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h.Bytes(), H) {
		if testing.Verbose() {
			t.Logf("H(computed) = %s\n", hex.EncodeToString(h.Bytes()))
			t.Logf("H(expected) = %s\n", hex.EncodeToString(H))
		}
		t.Fatal("H mismatch")
	}
	// test derived key
	q := dpub.Bytes()
	if !bytes.Equal(q, Q) {
		if testing.Verbose() {
			t.Logf("derived (computed) = %s\n", hex.EncodeToString(q))
			t.Logf("derived (expected) = %s\n", hex.EncodeToString(Q))
		}
		t.Fatal("x-coordinate mismatch")
	}

	// test query
	out := sha512.Sum512(dpub.Bytes())
	if !bytes.Equal(out[:], QUERY) {
		if testing.Verbose() {
			t.Log("query(computed) = " + hex.EncodeToString(out[:]))
			t.Log("query(expected) = " + hex.EncodeToString(QUERY))
		}
		t.Fatal("Query mismatch")
	}
}

func TestHKDF_gnunet(t *testing.T) {

	var (
		// SALT as defined in GNUnet
		salt = []byte("key-derivation")
		// expected PRK (as dumped in GNUnet)
		PRK = []byte{
			0xEB, 0xFE, 0x63, 0xBA, 0x68, 0x2D, 0xA5, 0x5C,
			0xF8, 0x37, 0xCE, 0x8F, 0x94, 0x3B, 0x01, 0x44,
			0x1B, 0xF9, 0x67, 0x3D, 0xFC, 0x91, 0xED, 0x61,
			0x79, 0x94, 0xE8, 0x2A, 0x62, 0x0A, 0xE8, 0x6E,
			0x59, 0xDB, 0x56, 0x63, 0x80, 0x94, 0x63, 0xAC,
			0x8D, 0x35, 0xE2, 0xEA, 0xBA, 0xE6, 0xF3, 0xE8,
			0xC1, 0x4B, 0xC9, 0x4F, 0xBD, 0xE3, 0xE6, 0x61,
			0x01, 0xB3, 0xB2, 0x1C, 0x6F, 0x19, 0x73, 0x8B,
		}
		info = []byte("master-homegns")
		// expected result (as dumped in GNUnet)
		OKM = []byte{
			0x30, 0x86, 0x34, 0x7F, 0x2E, 0x12, 0xD7, 0x65,
			0x35, 0x70, 0x44, 0xE2, 0xF6, 0x9B, 0x84, 0x59,
			0x6E, 0xE1, 0x7F, 0x62, 0x93, 0xAD, 0xAE, 0x56,
			0x50, 0x6A, 0xA6, 0xD6, 0x8D, 0x39, 0x39, 0x95,
		}
	)
	prk := hkdf.Extract(sha512.New, pub.Bytes(), salt)
	if testing.Verbose() {
		t.Log("PRK(computed) = " + hex.EncodeToString(prk))
	}
	if !bytes.Equal(prk, PRK) {
		t.Log("PRK(expected) = " + hex.EncodeToString(PRK))
		t.Fatal("PRK mismatch")
	}

	rdr := hkdf.Expand(sha256.New, prk, info)
	okm := make([]byte, len(OKM))
	if _, err := rdr.Read(okm); err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		t.Log("OKM(computed) = " + hex.EncodeToString(okm))
	}
	if !bytes.Equal(okm, OKM) {
		t.Log("OKM(expected) = " + hex.EncodeToString(OKM))
		t.Fatal("OKM mismatch")
	}
}

func TestHDKF(t *testing.T) {
	var (
		ikm = []byte{
			0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		}
		salt = []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c,
		}
		PRK = []byte{
			0x66, 0x57, 0x99, 0x82, 0x37, 0x37, 0xde, 0xd0,
			0x4a, 0x88, 0xe4, 0x7e, 0x54, 0xa5, 0x89, 0x0b,
			0xb2, 0xc3, 0xd2, 0x47, 0xc7, 0xa4, 0x25, 0x4a,
			0x8e, 0x61, 0x35, 0x07, 0x23, 0x59, 0x0a, 0x26,
			0xc3, 0x62, 0x38, 0x12, 0x7d, 0x86, 0x61, 0xb8,
			0x8c, 0xf8, 0x0e, 0xf8, 0x02, 0xd5, 0x7e, 0x2f,
			0x7c, 0xeb, 0xcf, 0x1e, 0x00, 0xe0, 0x83, 0x84,
			0x8b, 0xe1, 0x99, 0x29, 0xc6, 0x1b, 0x42, 0x37,
		}
		info = []byte{
			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
		}
		OKM = []byte{
			0x83, 0x23, 0x90, 0x08, 0x6c, 0xda, 0x71, 0xfb,
			0x47, 0x62, 0x5b, 0xb5, 0xce, 0xb1, 0x68, 0xe4,
			0xc8, 0xe2, 0x6a, 0x1a, 0x16, 0xed, 0x34, 0xd9,
			0xfc, 0x7f, 0xe9, 0x2c, 0x14, 0x81, 0x57, 0x93,
			0x38, 0xda, 0x36, 0x2c, 0xb8, 0xd9, 0xf9, 0x25,
			0xd7, 0xcb,
		}
	)

	prk := hkdf.Extract(sha512.New, ikm, salt)
	if testing.Verbose() {
		t.Log("PRK(computed) = " + hex.EncodeToString(prk))
	}
	if !bytes.Equal(prk, PRK) {
		t.Log("PRK(expected) = " + hex.EncodeToString(PRK))
		t.Fatal("PRK mismatch")
	}

	rdr := hkdf.Expand(sha512.New, prk, info)
	okm := make([]byte, len(OKM))
	if _, err := rdr.Read(okm); err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		t.Log("OKM(computed) = " + hex.EncodeToString(okm))
	}
	if !bytes.Equal(okm, OKM) {
		t.Log("OKM(expected) = " + hex.EncodeToString(OKM))
		t.Fatal("OKM mismatch")
	}
}
