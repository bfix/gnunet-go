package message

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

var (
	msgData = []byte{
		0x00, 0x28, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00,
		0x92, 0xdc, 0xbf, 0x39, 0x40, 0x2d, 0xc6, 0x3c,
		0x97, 0xa6, 0x81, 0xe0, 0xfc, 0xd8, 0x7c, 0x74,
		0x17, 0xd3, 0xa3, 0x8c, 0x52, 0xfd, 0xe0, 0x49,
		0xbc, 0xd0, 0x1c, 0x0a, 0x0b, 0x8c, 0x02, 0x51,
		0x42, 0x45, 0x52, 0x4e, 0x44, 0x00, 0x00, 0x04,
		0x00, 0x05, 0x70, 0xad, 0xd7, 0x15, 0xbc, 0xd5,
		0xac, 0x11, 0x00, 0x05,
	}
)

func TestHello(t *testing.T) {
	m := NewHelloMsg(nil)
	if err := Unmarshal(m, msgData); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%v\n", m)
	fmt.Printf("   %s\n", hex.EncodeToString(msgData))

	newData, err := Marshal(m)
	fmt.Printf("   %s\n", hex.EncodeToString(newData))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(newData, msgData) != 0 {
		t.Fatal("Marshal/unmarshal mismatch")
	}
}

type NestedStruct struct {
	A int64 `order:"big"`
	B int32
}

func (n *NestedStruct) String() string {
	return fmt.Sprintf("%v", *n)
}

type SubStruct struct {
	G int32
}

func (s *SubStruct) String() string {
	return fmt.Sprintf("%v", *s)
}

type MainStruct struct {
	C uint64 `order:"big"`
	D string
	F *SubStruct
	E []*NestedStruct
}

func TestNested(t *testing.T) {
	r := new(MainStruct)
	r.C = 19031962
	r.D = "Just a test"
	r.E = make([]*NestedStruct, 3)
	r.F = new(SubStruct)
	r.F.G = 0x23
	for i := 0; i < 3; i++ {
		n := new(NestedStruct)
		n.A = int64(255 - i)
		n.B = int32(815 * (i + 1))
		r.E[i] = n
	}

	data, err := Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("<<< %v\n", r)
	fmt.Printf("    [%s]\n", hex.EncodeToString(data))

	s := new(MainStruct)
	s.F = new(SubStruct)
	s.E = make([]*NestedStruct, 3)
	for i := 0; i < 3; i++ {
		s.E[i] = new(NestedStruct)
	}
	if err = Unmarshal(s, data); err != nil {
		t.Fatal(err)
	}
	fmt.Printf(">>> %v\n", s)
}

var (
	secret = []byte{
		0x78, 0xde, 0xcf, 0xc0, 0x26, 0x9e, 0x62, 0x3d,
		0x17, 0x24, 0xe6, 0x1b, 0x98, 0x25, 0xec, 0x2f,
		0x40, 0x6b, 0x1e, 0x39, 0xa5, 0x19, 0xac, 0x9b,
		0xb2, 0xdd, 0xf4, 0x6c, 0x12, 0x83, 0xdb, 0x86,
	}
)

func TestMarshal(t *testing.T) {
	msg := NewTransportTcpWelcomeMsg(secret)
	fmt.Println("<== " + msg.String())
	data, err := Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("    [%s]\n", hex.EncodeToString(data))

	msg2 := new(TransportTcpWelcomeMsg)
	msg2.PeerID = make([]byte, 32)
	if err = Unmarshal(msg2, data); err != nil {
		t.Fatal(err)
	}
	fmt.Println("==> " + msg2.String())
	data2, err := Marshal(msg2)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("    [%s]\n", hex.EncodeToString(data2))
}
