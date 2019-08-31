package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

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

	prv_1, prv_2 *PrivateKey
	pub_1, pub_2 *PublicKey
)

func TestDHE(t *testing.T) {
	// generate two key pairs
	prv_1 = PrivateKeyFromD(math.NewIntFromBytes(d_1))
	pub_1 = prv_1.Public()
	prv_2 = PrivateKeyFromD(math.NewIntFromBytes(d_2))
	pub_2 = prv_2.Public()

	// compute shared secret
	ss_1 := SharedSecret(prv_1, pub_2)
	ss_2 := SharedSecret(prv_2, pub_1)
	if testing.Verbose() {
		fmt.Printf("SS_1 = %s\n", hex.EncodeToString(ss_1.Bits))
		fmt.Printf("SS_2 = %s\n", hex.EncodeToString(ss_2.Bits))
	}

	if bytes.Compare(ss_1.Bits, ss) != 0 {
		fmt.Printf("SS(expected) = %s\n", hex.EncodeToString(ss))
		fmt.Printf("SS(computed) = %s\n", hex.EncodeToString(ss_1.Bits))
		t.Fatal("Wrong shared secret:")
	}
	if bytes.Compare(ss_1.Bits, ss_2.Bits) != 0 {
		t.Fatal("Shared secret mismatch")
	}
}
