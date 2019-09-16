package crypto

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/math"
	"gnunet/util"
	"golang.org/x/crypto/hkdf"
)

func TestDeriveH(t *testing.T) {
	var (
		D = []byte{
			0x40, 0x00, 0xd4, 0xe6, 0x85, 0xa3, 0x40, 0xe2,
			0xa5, 0xab, 0x0f, 0xe0, 0x56, 0xbd, 0x5b, 0x93,
			0x6b, 0x86, 0xcd, 0x2d, 0xd2, 0xa0, 0x71, 0x4c,
			0x1e, 0x2b, 0x16, 0x08, 0x83, 0xaa, 0x7f, 0x88,
		}
		PUB = []byte{
			0x93, 0x34, 0x71, 0xF6, 0x99, 0x19, 0x0C, 0x62,
			0x85, 0xC7, 0x9B, 0x83, 0x9D, 0xCA, 0x83, 0x91,
			0x38, 0xFA, 0x87, 0xFB, 0xB8, 0xD4, 0xF6, 0xF0,
			0xF0, 0x4B, 0x7F, 0x0A, 0x48, 0xBF, 0x95, 0xF7,
		}

		ID      = "JCT73XMS346651E7KE1SVJM3J4WFN1ZVQ3AFDW7G9DZGMJ5ZJQVG"
		LABEL   = "home"
		CONTEXT = "gns"

		H = []byte{
			0x0d, 0x4a, 0x75, 0x30, 0xfd, 0x07, 0xe1, 0x88,
			0xfc, 0xa0, 0xf4, 0x29, 0x52, 0x66, 0x24, 0x0f,
			0x1e, 0x08, 0x91, 0xb0, 0x61, 0x39, 0x46, 0xca,
			0xfb, 0x4c, 0xe3, 0xa8, 0x54, 0xca, 0x47, 0x7a,
		}
		Q = []byte{
			0x26, 0x84, 0x1b, 0x24, 0x35, 0xa4, 0x63, 0xe9,
			0xf0, 0x48, 0xae, 0x3e, 0xf7, 0xe8, 0x1b, 0xca,
			0x55, 0x9f, 0x4c, 0x1e, 0x16, 0x18, 0xa6, 0xd3,
			0x5b, 0x91, 0x0d, 0x54, 0x31, 0x6e, 0xbf, 0x97,
		}

		QUERY = []byte{
			0x13, 0xab, 0x16, 0x69, 0x72, 0xf5, 0x8a, 0xcf,
			0x21, 0x96, 0xc8, 0x19, 0x9c, 0x92, 0x46, 0x6f,
			0x15, 0xa2, 0x45, 0x19, 0x0a, 0x18, 0xd2, 0x3b,
			0x7b, 0x83, 0x21, 0x4e, 0x9d, 0x03, 0x3b, 0x81,
			0x7d, 0xc2, 0x23, 0xf3, 0x26, 0xe4, 0x7b, 0x43,
			0x52, 0xa1, 0x03, 0x59, 0x00, 0xd7, 0x2e, 0x3f,
			0x17, 0x0f, 0xc3, 0xb5, 0xf5, 0xcf, 0x3a, 0xdd,
			0xea, 0x8a, 0xc6, 0xbd, 0x2b, 0xfd, 0x50, 0x54,
		}
	)

	// compute keypair from seed
	prv := ed25519.NewPrivateKeyFromD(math.NewIntFromBytes(D))
	pub := prv.Public()
	if bytes.Compare(pub.Bytes(), PUB) != 0 {
		t.Fatal("Wrong public key")
	}
	if ID != util.EncodeBinaryToString(pub.Bytes()) {
		t.Fatal("Wrong ego ID")
	}

	hBuf := make([]byte, 32)
	hFull := DeriveH(pub, LABEL, CONTEXT)
	h := hFull.Mod(ED25519_N)
	util.CopyBlock(hBuf, h.Bytes())
	if bytes.Compare(hBuf, H) != 0 {
		if testing.Verbose() {
			t.Logf("H(computed) = %s\n", hex.EncodeToString(hBuf))
			t.Logf("H(expected) = %s\n", hex.EncodeToString(H))
		}
		t.Fatal("H mismatch")
	}

	dpub := pub.Mult(h)
	dpub2 := DerivePublicKey(pub, LABEL, CONTEXT)
	if !dpub.Q.Equals(dpub2.Q) {
		t.Fatal("Q mismatch")
	}

	q := dpub.Q.Bytes()
	if bytes.Compare(q, Q) != 0 {
		if testing.Verbose() {
			t.Logf("derived_x(computed) = %s\n", hex.EncodeToString(q))
			t.Logf("derived_x(expected) = %s\n", hex.EncodeToString(Q))
		}
		t.Fatal("x-coordinate mismatch")
	}
	pk1 := dpub.Bytes()
	pk2 := DerivePublicKey(pub, LABEL, CONTEXT).Bytes()
	if bytes.Compare(pk1, pk2) != 0 {
		if testing.Verbose() {
			t.Logf("derived(1) = %s\n", hex.EncodeToString(pk1))
			t.Logf("derived(2) = %s\n", hex.EncodeToString(pk2))
		}
		t.Fatal("Derived key mismatch")
	}

	out := sha512.Sum512(pk1)
	if bytes.Compare(out[:], QUERY) != 0 {
		if testing.Verbose() {
			t.Log("query(expected) = " + hex.EncodeToString(QUERY))
			t.Log("query(computed) = " + hex.EncodeToString(out[:]))
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
	if bytes.Compare(prk, PRK) != 0 {
		t.Log("PRK(expected) = " + hex.EncodeToString(PRK))
		t.Fatal("PRK mismatch")
	}

	rdr := hkdf.Expand(sha256.New, prk, info)
	okm := make([]byte, len(OKM))
	rdr.Read(okm)
	if testing.Verbose() {
		t.Log("OKM(computed) = " + hex.EncodeToString(okm))
	}
	if bytes.Compare(okm, OKM) != 0 {
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
	if bytes.Compare(prk, PRK) != 0 {
		t.Log("PRK(expected) = " + hex.EncodeToString(PRK))
		t.Fatal("PRK mismatch")
	}

	rdr := hkdf.Expand(sha512.New, prk, info)
	okm := make([]byte, len(OKM))
	rdr.Read(okm)
	if testing.Verbose() {
		t.Log("OKM(computed) = " + hex.EncodeToString(okm))
	}
	if bytes.Compare(okm, OKM) != 0 {
		t.Log("OKM(expected) = " + hex.EncodeToString(OKM))
		t.Fatal("OKM mismatch")
	}
}
