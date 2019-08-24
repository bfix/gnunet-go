package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

var (
	sig1 = []byte{
		0x0c, 0x27, 0xb3, 0xd4, 0xcb, 0xd7, 0x1c, 0x99,
		0xc3, 0x12, 0xa8, 0x16, 0x47, 0x30, 0x24, 0xcf,
		0x6a, 0x9c, 0xca, 0xb6, 0x93, 0xbb, 0x5f, 0xdb,
		0x1e, 0xf2, 0x8f, 0x2d, 0xec, 0x6d, 0x24, 0xb3,
		0xd0, 0xc0, 0x2b, 0x7d, 0xeb, 0x96, 0x4d, 0xaf,
		0xe4, 0x4c, 0x4b, 0xc0, 0xe0, 0x3e, 0x49, 0xf4,
		0x0d, 0x90, 0x5a, 0x97, 0xa1, 0x9d, 0x85, 0xd8,
		0x9f, 0x67, 0x76, 0xf4, 0x0c, 0x25, 0x46, 0x08,
	}
	sig2 = []byte{
		0x11, 0x52, 0xa8, 0xc8, 0x29, 0x2d, 0x32, 0x53,
		0x8c, 0x56, 0x53, 0xbc, 0x5f, 0x5f, 0x7c, 0x65,
		0x48, 0x75, 0x26, 0x07, 0x56, 0x81, 0x9b, 0x67,
		0x83, 0x75, 0x08, 0xcf, 0x54, 0xd4, 0x4a, 0xf5,
		0x0c, 0x33, 0x2d, 0xcc, 0x6a, 0x88, 0xfe, 0x79,
		0x11, 0xfe, 0x5f, 0x78, 0xd6, 0xa8, 0x94, 0x25,
		0x38, 0x38, 0x5d, 0x25, 0xf2, 0x96, 0xe1, 0xdc,
		0x4b, 0xd8, 0x4a, 0xc2, 0xd3, 0x99, 0xf7, 0x54,
	}

	msg_1 = []byte{
		0x00, 0x00, 0x00, 0x22,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x05, 0x70, 0xad, 0xe2, 0x8b, 0x6b, 0xa5,
		0x00, 0x00, 0x00, 0x0e,
		0x74, 0x63, 0x70, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xac, 0x11, 0x00, 0x05,
		0x08, 0x26,
	}

	msg_2 = []byte{
		0x49, 0x20, 0x83, 0x5b, 0x92, 0xb4, 0x7d, 0x14,
		0x4e, 0x88, 0x96, 0x48, 0xa5, 0xba, 0x53, 0x39,
		0x42, 0xa7, 0x85, 0xb0, 0x66, 0x91, 0x43, 0x3f,
		0x2c, 0x59, 0x85, 0x0d, 0x9f, 0x3e, 0xb0, 0x08,
	}
)

func TestEdDSA(t *testing.T) {
	sigT, err := prv.Sign(msg_1)
	if err != nil {
		t.Fatal(err)
	}
	sigT.isEdDSA = true
	sigX := sigT.Bytes()
	if testing.Verbose() {
		fmt.Printf("SIG=%s\n", hex.EncodeToString(sigX))
	}
	if bytes.Compare(sigX, sig1) != 0 {
		t.Logf("SIG! = %s\n", hex.EncodeToString(sig1))
		t.Fatal("Signature mismatch")
	}
	rc, err := pub.Verify(msg_1, sigT)
	if err != nil {
		t.Fatal(err)
	}
	if !rc {
		t.Fatal("Verify failed")
	}
}

func TestEcDSA(t *testing.T) {
	sigT, err := prv.SignLin(msg_2)
	if err != nil {
		t.Fatal(err)
	}
	sigX := sigT.Bytes()
	if testing.Verbose() {
		fmt.Printf("SIG=%s\n", hex.EncodeToString(sigX))
	}
	if bytes.Compare(sigX, sig2) != 0 {
		t.Logf("SIG! = %s\n", hex.EncodeToString(sig2))
		t.Fatal("Signature mismatch")
	}
	rc, err := pub.VerifyLin(msg_2, sigT)
	if err != nil {
		t.Fatal(err)
	}
	if !rc {
		t.Fatal("Verify failed")
	}
}
