package crypto

import (
	"bytes"
	"crypto/sha512"
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
	ss_1, ss_2   []byte
)

func calcSharedSecret() bool {
	calc := func(prv *PrivateKey, pub *PublicKey) []byte {
		x := sha512.Sum512(pub.Mult(prv.D()).AffineX().Bytes())
		return x[:]
	}
	// compute shared secret
	ss_1 = calc(prv_1, pub_2)
	ss_2 = calc(prv_2, pub_1)
	return bytes.Compare(ss_1, ss_2) == 0
}

func TestDHE(t *testing.T) {
	// generate two key pairs
	prv_1 = NewPrivateKeyFromD(math.NewIntFromBytes(d_1))
	pub_1 = prv_1.Public()
	prv_2 = NewPrivateKeyFromD(math.NewIntFromBytes(d_2))
	pub_2 = prv_2.Public()

	if !calcSharedSecret() {
		t.Fatal("Shared secret mismatch")
	}
	if testing.Verbose() {
		fmt.Printf("SS_1 = %s\n", hex.EncodeToString(ss_1))
		fmt.Printf("SS_2 = %s\n", hex.EncodeToString(ss_2))
	}

	if bytes.Compare(ss_1[:], ss) != 0 {
		fmt.Printf("SS(expected) = %s\n", hex.EncodeToString(ss))
		fmt.Printf("SS(computed) = %s\n", hex.EncodeToString(ss_1[:]))
		t.Fatal("Wrong shared secret:")
	}

}

func TestDHERandom(t *testing.T) {
	failed := 0
	once := false
	for i := 0; i < 1000; i++ {
		prv_1 = NewPrivateKeyFromD(math.NewIntRnd(ED25519_N))
		pub_1 = prv_1.Public()
		prv_2 = NewPrivateKeyFromD(math.NewIntRnd(ED25519_N))
		pub_2 = prv_2.Public()

		if !calcSharedSecret() {
			if !once {
				once = true
				fmt.Printf("d1=%s\n", hex.EncodeToString(prv_1.D().Bytes()))
				fmt.Printf("d2=%s\n", hex.EncodeToString(prv_2.D().Bytes()))
				fmt.Printf("ss1=%s\n", hex.EncodeToString(ss_1))
				fmt.Printf("ss2=%s\n", hex.EncodeToString(ss_2))
				dd := prv_1.D().Mul(prv_2.D()).Mod(ED25519_N)
				pk := sha512.Sum512(NewPrivateKeyFromD(dd).Public().AffineX().Bytes())
				fmt.Printf("ss0=%s\n", hex.EncodeToString(pk[:]))
			}
			failed++
		}
	}
	if failed > 0 {
		t.Fatalf("Shared secret mismatches: %d/1000", failed)
	}
}
