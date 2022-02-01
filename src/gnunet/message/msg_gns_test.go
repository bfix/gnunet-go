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

package message

import (
	"bytes"
	"encoding/hex"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"
	"testing"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/math"
)

// TestRecordsetPKEY implements the test case as defined in the GNS draft
// (see section 13. Test vectors, case "PKEY")
func TestRecordsetPKEY(t *testing.T) {
	var (
		D = []byte{
			0x50, 0xd7, 0xb6, 0x52, 0xa4, 0xef, 0xea, 0xdf,
			0xf3, 0x73, 0x96, 0x90, 0x97, 0x85, 0xe5, 0x95,
			0x21, 0x71, 0xa0, 0x21, 0x78, 0xc8, 0xe7, 0xd4,
			0x50, 0xfa, 0x90, 0x79, 0x25, 0xfa, 0xfd, 0x98,
		}
		ZTYPE = []byte{0x00, 0x01, 0x00, 0x00}
		ZKEY  = []byte{
			0x67, 0x7c, 0x47, 0x7d, 0x2d, 0x93, 0x09, 0x7c,
			0x85, 0xb1, 0x95, 0xc6, 0xf9, 0x6d, 0x84, 0xff,
			0x61, 0xf5, 0x98, 0x2c, 0x2c, 0x4f, 0xe0, 0x2d,
			0x5a, 0x11, 0xfe, 0xdf, 0xb0, 0xc2, 0x90, 0x1f,
		}
		ZID    = "000G0037FH3QTBCK15Y8BCCNRVWPV17ZC7TSGB1C9ZG2TPGHZVFV1GMG3W"
		RECSET = &RecordSet{
			Count: 2,
			Records: []*ResourceRecord{
				{
					Expires: util.AbsoluteTime{
						Val: uint64(14888744139323793),
					},
					Size:  4,
					Type:  1,
					Flags: 0,
					Data: []byte{
						0x01, 0x02, 0x03, 0x04,
					},
				},
				{
					Expires: util.AbsoluteTime{
						Val: uint64(26147096139323793),
					},
					Size:  36,
					Type:  crypto.ZONE_PKEY,
					Flags: 2,
					Data: []byte{
						0x00, 0x01, 0x00, 0x00,
						0x0e, 0x60, 0x1b, 0xe4, 0x2e, 0xb5, 0x7f, 0xb4,
						0x69, 0x76, 0x10, 0xcf, 0x3a, 0x3b, 0x18, 0x34,
						0x7b, 0x65, 0xa3, 0x3f, 0x02, 0x5b, 0x5b, 0x17,
						0x4a, 0xbe, 0xfb, 0x30, 0x80, 0x7b, 0xfe, 0xcf,
					},
				},
			},
			Padding: make([]byte, 0),
		}
		RDATA = []byte{
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
		NONCE = []byte{
			0x67, 0xeb, 0xda, 0x27, 0x00, 0x34, 0xe5, 0x3b,
			0xe1, 0x93, 0x79, 0x91, 0x00, 0x00, 0x00, 0x01,
		}
		SKEY = []byte{
			0x55, 0x1f, 0x15, 0x7a, 0xcf, 0x2b, 0xf1, 0xd4,
			0xa9, 0x75, 0x03, 0x69, 0x99, 0xea, 0x7c, 0x82,
			0x86, 0xac, 0xb3, 0x18, 0xf1, 0x49, 0x3e, 0x63,
			0xb5, 0x00, 0x60, 0x3a, 0x9b, 0x02, 0xe3, 0xe4,
		}
		BDATA = []byte{
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
		LABEL = "test"
	)

	// check zone key pair
	prv := ed25519.NewPrivateKeyFromD(math.NewIntFromBytes(D))
	pub := prv.Public()
	zkey := pub.Bytes()
	if !bytes.Equal(zkey, ZKEY) {
		t.Logf("pub = %s\n", hex.EncodeToString(zkey))
		t.Logf("   != %s\n", hex.EncodeToString(ZKEY))
		t.Fatal("zone key mismatch")
	}
	buf := append(ZTYPE, ZKEY...)
	zid := util.EncodeBinaryToString(buf)
	if zid != ZID {
		t.Fatal("Zone ID mismatch")
	}

	// assemble and check recordset
	RECSET.SetPadding()
	rdata, err := data.Marshal(RECSET)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rdata, RDATA) {
		t.Logf("rdata = %s\n", hex.EncodeToString(rdata))
		t.Logf("RDATA = %s\n", hex.EncodeToString(RDATA))
		t.Fatal("RDATA mismatch")
	}

	// check symmetric keys and nonce
	zk := crypto.NewZoneKey(crypto.ZONE_PKEY, pub)
	expires := RECSET.Expires()
	skey := crypto.DeriveKey(LABEL, zk, expires, 1)
	if !bytes.Equal(skey[32:], NONCE) {
		t.Logf("nonce = %s\n", hex.EncodeToString(skey[32:]))
		t.Logf("NONCE = %s\n", hex.EncodeToString(NONCE))
		t.Fatal("NONCE mismatch")
	}
	if !bytes.Equal(skey[:32], SKEY) {
		t.Logf("skey = %s\n", hex.EncodeToString(skey[:32]))
		t.Logf("SKEY = %s\n", hex.EncodeToString(SKEY))
		t.Fatal("SKEY mismatch")
	}

	// check block encryption
	bdata, err := crypto.CipherData(true, rdata, zk, LABEL, expires, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bdata, BDATA) {
		t.Logf("bdata = %s\n", hex.EncodeToString(bdata))
		t.Logf("BDATA = %s\n", hex.EncodeToString(BDATA))
		t.Fatal("BDATA mismatch")
	}
}

// TestRecordsetEDKEY implements the test case as defined in the GNS draft
// (see section 13. Test vectors, case "EDKEY")
func TestRecordsetEDKEY(t *testing.T) {
	var (
		SEED = []byte{
			0x5a, 0xf7, 0x02, 0x0e, 0xe1, 0x91, 0x60, 0x32,
			0x88, 0x32, 0x35, 0x2b, 0xbc, 0x6a, 0x68, 0xa8,
			0xd7, 0x1a, 0x7c, 0xbe, 0x1b, 0x92, 0x99, 0x69,
			0xa7, 0xc6, 0x6d, 0x41, 0x5a, 0x0d, 0x8f, 0x65,
		}
		ZTYPE = []byte{0x00, 0x01, 0x00, 0x14}
		ZKEY  = []byte{
			0x3c, 0xf4, 0xb9, 0x24, 0x03, 0x20, 0x22, 0xf0,
			0xdc, 0x50, 0x58, 0x14, 0x53, 0xb8, 0x5d, 0x93,
			0xb0, 0x47, 0xb6, 0x3d, 0x44, 0x6c, 0x58, 0x45,
			0xcb, 0x48, 0x44, 0x5d, 0xdb, 0x96, 0x68, 0x8f,
		}
		ZID    = "000G051WYJWJ80S04BRDRM2R2H9VGQCKP13VCFA4DHC4BJT88HEXQ5K8HW"
		RECSET = &RecordSet{
			Count: 2,
			Records: []*ResourceRecord{
				{
					Expires: util.AbsoluteTime{
						Val: uint64(2463385894000000),
					},
					Size:  4,
					Type:  1,
					Flags: 0,
					Data: []byte{
						0x01, 0x02, 0x03, 0x04,
					},
				},
				{
					Expires: util.AbsoluteTime{
						Val: uint64(49556645701000000),
					},
					Size:  36,
					Type:  uint32(enums.GNS_TYPE_NICK),
					Flags: 2,
					Data: []byte{
						0x4d, 0x79, 0x20, 0x4e, 0x69, 0x63, 0x6b, 0x00,
						0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69,
						0x6f, 0x6e, 0x20, 0x4e, 0x4f, 0x4e, 0x43, 0x45,
						0x7c, 0x45, 0x58, 0x50, 0x49, 0x52, 0x41, 0x54,
						0x49, 0x4f, 0x4e, 0x3a,
					},
				},
			},
			Padding: make([]byte, 0),
		}
		RDATA = []byte{
			0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0xc0, 0x6f,
			0xb9, 0x28, 0x15, 0x80, 0x00, 0x00, 0x00, 0x04,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x02, 0x03, 0x04, 0x00, 0xb0, 0x0f, 0x81,
			0xb7, 0x44, 0x9b, 0x40, 0x00, 0x00, 0x00, 0x24,
			0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
			0x4d, 0x79, 0x20, 0x4e, 0x69, 0x63, 0x6b, 0x00,
			0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69,
			0x6f, 0x6e, 0x20, 0x4e, 0x4f, 0x4e, 0x43, 0x45,
			0x7c, 0x45, 0x58, 0x50, 0x49, 0x52, 0x41, 0x54,
			0x49, 0x4f, 0x4e, 0x3a, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}
		NONCE = []byte{
			0x95, 0x4c, 0xb5, 0xd6, 0x31, 0x9f, 0x9e, 0x31,
			0xff, 0x80, 0x4a, 0xe6, 0x83, 0xbc, 0x19, 0x37,
			0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80,
		}
		SKEY = []byte{
			0x08, 0x34, 0xa3, 0xa3, 0xae, 0x09, 0xcb, 0x3b,
			0xd9, 0x8c, 0xec, 0xdb, 0x47, 0x7c, 0x3b, 0x32,
			0x45, 0xd0, 0xce, 0xda, 0x94, 0x8f, 0x9e, 0xbb,
			0xba, 0x3b, 0x17, 0x91, 0x61, 0x7b, 0xee, 0x69,
		}
		BDATA = []byte{
			0x3d, 0x6c, 0xca, 0xe2, 0xb1, 0x4e, 0xf4, 0x25,
			0xe3, 0xd6, 0xbb, 0xd6, 0x27, 0x1a, 0x71, 0xe5,
			0x42, 0x1c, 0x25, 0x1c, 0xfb, 0x5e, 0xb6, 0xd7,
			0xbc, 0x9e, 0x74, 0xb2, 0xe8, 0xc8, 0xd8, 0x6c,
			0xe0, 0x65, 0x37, 0x12, 0x0c, 0x2e, 0xe2, 0x28,
			0x5b, 0x93, 0xc5, 0xaf, 0xb7, 0x79, 0xf9, 0xcf,
			0x50, 0x2e, 0x16, 0xa5, 0xad, 0x30, 0xe6, 0x22,
			0xed, 0x58, 0x92, 0xd2, 0x46, 0xc0, 0x34, 0x11,
			0x70, 0xf0, 0xc5, 0x1c, 0x39, 0x40, 0xab, 0x33,
			0x47, 0xdc, 0x91, 0x56, 0x5f, 0x36, 0x6d, 0xb6,
			0x23, 0x56, 0x73, 0x9a, 0xd8, 0xde, 0x68, 0x21,
			0x12, 0x68, 0xf0, 0xc0, 0x44, 0x00, 0x81, 0xd8,
			0xaf, 0x8a, 0x6e, 0x16, 0x45, 0xa6, 0x92, 0x46,
			0xb4, 0x34, 0xe2, 0xc8, 0x76, 0x9f, 0x00, 0x1b,
			0xd5, 0x1a, 0xb3, 0x73, 0x5e, 0x02, 0xb4, 0x81,
			0xa6, 0x83, 0x0f, 0x00, 0xd2, 0xf6, 0xf3, 0x15,
			0xdf, 0x54, 0x20, 0x90, 0x36, 0x07, 0xf8, 0x62,
			0xfc, 0xf4, 0xc6, 0xd4, 0x86, 0x1c, 0x7a, 0x06,
			0x08, 0x81, 0x28, 0xbb,
		}
		LABEL = "test"
	)

	// check zone key pair
	prv := ed25519.NewPrivateKeyFromSeed(SEED)
	pub := prv.Public()
	zkey := pub.Bytes()
	if !bytes.Equal(zkey, ZKEY) {
		t.Logf("pub = %s\n", hex.EncodeToString(zkey))
		t.Logf("   != %s\n", hex.EncodeToString(ZKEY))
		t.Fatal("zone key mismatch")
	}
	buf := append(ZTYPE, ZKEY...)
	zid := util.EncodeBinaryToString(buf)
	if zid != ZID {
		t.Fatal("Zone ID mismatch")
	}

	// assemble and check recordset
	RECSET.SetPadding()
	rdata, err := data.Marshal(RECSET)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rdata, RDATA) {
		t.Logf("rdata = %s\n", hex.EncodeToString(rdata))
		t.Logf("RDATA = %s\n", hex.EncodeToString(RDATA))
		t.Fatal("RDATA mismatch")
	}

	// check symmetric keys and nonce
	zk := crypto.NewZoneKey(crypto.ZONE_EDKEY, pub)
	expires := RECSET.Expires()
	skey := crypto.DeriveKey(LABEL, zk, expires, 1)
	if !bytes.Equal(skey[32:], NONCE) {
		t.Logf("nonce = %s\n", hex.EncodeToString(skey[32:]))
		t.Logf("NONCE = %s\n", hex.EncodeToString(NONCE))
		t.Fatal("NONCE mismatch")
	}
	if !bytes.Equal(skey[:32], SKEY) {
		t.Logf("skey = %s\n", hex.EncodeToString(skey[:32]))
		t.Logf("SKEY = %s\n", hex.EncodeToString(SKEY))
		t.Fatal("SKEY mismatch")
	}

	// check block encryption
	bdata, err := crypto.CipherData(true, rdata, zk, LABEL, expires, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bdata, BDATA) {
		t.Logf("bdata = %s\n", hex.EncodeToString(bdata))
		t.Logf("BDATA = %s\n", hex.EncodeToString(BDATA))
		t.Fatal("BDATA mismatch")
	}
}
