package crypto

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"

	"gnunet/crypto/hkdf"
)

func TestHKDF_gnunet(t *testing.T) {

	var (
		// Ed25519 public key (binary representation)
		pub = []byte{
			0x92, 0xDC, 0xBF, 0x39, 0x40, 0x2D, 0xC6, 0x3C,
			0x97, 0xA6, 0x81, 0xE0, 0xFC, 0xD8, 0x7C, 0x74,
			0x17, 0xD3, 0xA3, 0x8C, 0x52, 0xFD, 0xE0, 0x49,
			0xBC, 0xD0, 0x1C, 0x0A, 0x0B, 0x8C, 0x02, 0x51,
		}
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
	prk := hkdf.Extract(sha512.New, pub, salt)
	if testing.Verbose() {
		fmt.Println("PRK(computed) = " + hex.EncodeToString(prk))
	}
	if bytes.Compare(prk, PRK) != 0 {
		fmt.Println("PRK(expected) = " + hex.EncodeToString(PRK))
		t.Fatal("PRK mismatch")
	}

	rdr := hkdf.Expand(sha256.New, prk, info)
	okm := make([]byte, len(OKM))
	rdr.Read(okm)
	if testing.Verbose() {
		fmt.Println("OKM(computed) = " + hex.EncodeToString(okm))
	}
	if bytes.Compare(okm, OKM) != 0 {
		fmt.Println("OKM(expected) = " + hex.EncodeToString(OKM))
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
		fmt.Println("PRK(computed) = " + hex.EncodeToString(prk))
	}
	if bytes.Compare(prk, PRK) != 0 {
		fmt.Println("PRK(expected) = " + hex.EncodeToString(PRK))
		t.Fatal("PRK mismatch")
	}

	rdr := hkdf.Expand(sha512.New, prk, info)
	okm := make([]byte, len(OKM))
	rdr.Read(okm)
	if testing.Verbose() {
		fmt.Println("OKM(computed) = " + hex.EncodeToString(okm))
	}
	if bytes.Compare(okm, OKM) != 0 {
		fmt.Println("OKM(expected) = " + hex.EncodeToString(OKM))
		t.Fatal("OKM mismatch")
	}
}