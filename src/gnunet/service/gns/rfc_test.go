// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2023 Bernd Fix  >Y<
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

package gns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/service/dht/blocks"
	"gnunet/util"
	"testing"
)

type Rec struct {
	Expire []byte
	Size   []byte
	Type   []byte
	Flags  []byte
	Data   []byte
}

type Enc struct {
	Nonce   []byte
	Expire  []byte
	Counter []byte
	Key     []byte
}

type TestCase struct {
	Zpk     []byte
	Zid     []byte
	Ztld    string
	Label   string
	Q       []byte
	Recs    []*Rec
	Rdata   []byte
	Enc     *Enc
	Bdata   []byte
	RRblock []byte
}

var tests = []*TestCase{
	{
		Zpk: []byte{
			0x98, 0xfd, 0xfa, 0x25, 0x79, 0x90, 0xfa, 0x50, 0xd4, 0xe7, 0xc8, 0x78, 0x21, 0xa0, 0x71, 0x21,
			0x95, 0xe5, 0x85, 0x97, 0x90, 0x96, 0x73, 0xf3, 0xdf, 0xea, 0xef, 0xa4, 0x52, 0xb6, 0xd7, 0x50,
		},
		Zid: []byte{
			0x00, 0x01, 0x00, 0x00,
			0x67, 0x7c, 0x47, 0x7d, 0x2d, 0x93, 0x09, 0x7c, 0x85, 0xb1, 0x95, 0xc6, 0xf9, 0x6d, 0x84, 0xff,
			0x61, 0xf5, 0x98, 0x2c, 0x2c, 0x4f, 0xe0, 0x2d, 0x5a, 0x11, 0xfe, 0xdf, 0xb0, 0xc2, 0x90, 0x1f,
		},
		Ztld:  "000G0037FH3QTBCK15Y8BCCNRVWPV17ZC7TSGB1C9ZG2TPGHZVFV1GMG3W",
		Label: "testdelegation",
		Q: []byte{
			0x4a, 0xdc, 0x67, 0xc5, 0xec, 0xee, 0x9f, 0x76, 0x98, 0x6a, 0xbd, 0x71, 0xc2, 0x22, 0x4a, 0x3d,
			0xce, 0x2e, 0x91, 0x70, 0x26, 0xc9, 0xa0, 0x9d, 0xfd, 0x44, 0xce, 0xf3, 0xd2, 0x0f, 0x55, 0xa2,
			0x73, 0x32, 0x72, 0x5a, 0x6c, 0x8a, 0xfb, 0xbb, 0xb0, 0xf7, 0xec, 0x9a, 0xf1, 0xcc, 0x42, 0x64,
			0x12, 0x99, 0x40, 0x6b, 0x04, 0xfd, 0x9b, 0x5b, 0x57, 0x91, 0xf8, 0x6c, 0x4b, 0x08, 0xd5, 0xf4,
		},
		Recs: []*Rec{
			{
				Expire: []byte{0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80},
				Size:   []byte{0x00, 0x20},
				Type:   []byte{0x00, 0x01, 0x00, 0x00},
				Flags:  []byte{0x00, 0x01},
				Data: []byte{
					0x21, 0xe3, 0xb3, 0x0f, 0xf9, 0x3b, 0xc6, 0xd3, 0x5a, 0xc8, 0xc6, 0xe0, 0xe1, 0x3a, 0xfd, 0xff,
					0x79, 0x4c, 0xb7, 0xb4, 0x4b, 0xbb, 0xc7, 0x48, 0xd2, 0x59, 0xd0, 0xa0, 0x28, 0x4d, 0xbe, 0x84,
				},
			},
		},
		Rdata: []byte{
			0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
			0x21, 0xe3, 0xb3, 0x0f, 0xf9, 0x3b, 0xc6, 0xd3, 0x5a, 0xc8, 0xc6, 0xe0, 0xe1, 0x3a, 0xfd, 0xff,
			0x79, 0x4c, 0xb7, 0xb4, 0x4b, 0xbb, 0xc7, 0x48, 0xd2, 0x59, 0xd0, 0xa0, 0x28, 0x4d, 0xbe, 0x84,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		Enc: &Enc{
			Nonce: []byte{
				0xe9, 0x0a, 0x00, 0x61, 0x00, 0x08, 0xc0, 0x6f,
				0xb9, 0x28, 0x15, 0x80, 0x00, 0x00, 0x00, 0x01,
			},
			Expire:  []byte{0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80},
			Counter: []byte{0x00, 0x00, 0x00, 0x01},
			Key: []byte{
				0x86, 0x4e, 0x71, 0x38, 0xea, 0xe7, 0xfd, 0x91, 0xa3, 0x01, 0x36, 0x89, 0x9c, 0x13, 0x2b, 0x23,
				0xac, 0xeb, 0xdb, 0x2c, 0xef, 0x43, 0xcb, 0x19, 0xf6, 0xbf, 0x55, 0xb6, 0x7d, 0xb9, 0xb3, 0xb3,
			},
		},
		Bdata: []byte{
			0x41, 0xdc, 0x7b, 0x5f, 0x21, 0x76, 0xba, 0x59, 0x19, 0x98, 0xaf, 0xb9, 0xe3, 0xc8, 0x25, 0x79,
			0x50, 0x50, 0xaf, 0xc4, 0xb5, 0x3d, 0x68, 0xe4, 0x1e, 0xd9, 0x21, 0xda, 0x89, 0xde, 0x51, 0xe7,
			0xda, 0x35, 0xa2, 0x95, 0xb5, 0x9c, 0x2b, 0x8a, 0xae, 0xa4, 0x39, 0x91, 0x48, 0xd5, 0x0c, 0xff,
			0x68, 0x59, 0x6b, 0x4d, 0xcb, 0x8b, 0xc2, 0xc1, 0x1b, 0xb1, 0x84, 0xd5, 0x90, 0x56, 0x13, 0xe8,
		},
		RRblock: []byte{
			0x00, 0x00, 0x00, 0xb0, 0x00, 0x01, 0x00, 0x00, 0x18, 0x2b, 0xb6, 0x36, 0xed, 0xa7, 0x9f, 0x79,
			0x57, 0x11, 0xbc, 0x27, 0x08, 0xad, 0xbb, 0x24, 0x2a, 0x60, 0x44, 0x6a, 0xd3, 0xc3, 0x08, 0x03,
			0x12, 0x1d, 0x03, 0xd3, 0x48, 0xb7, 0xce, 0xb6, 0x01, 0xbe, 0xab, 0x94, 0x4a, 0xff, 0x7c, 0xcc,
			0x51, 0xbf, 0xfb, 0x21, 0x27, 0x79, 0xc3, 0x41, 0x87, 0x66, 0x0c, 0x62, 0x5d, 0x1c, 0xeb, 0x59,
			0xd5, 0xa0, 0xa9, 0xa2, 0xdf, 0xe4, 0x07, 0x2d, 0x0f, 0x08, 0xcd, 0x2a, 0xb1, 0xe9, 0xed, 0x63,
			0xd3, 0x89, 0x8f, 0xf7, 0x32, 0x52, 0x1b, 0x57, 0x31, 0x7a, 0x6c, 0x49, 0x50, 0xe1, 0x98, 0x4d,
			0x74, 0xdf, 0x01, 0x5f, 0x9e, 0xb7, 0x2c, 0x4a, 0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80,
			0x41, 0xdc, 0x7b, 0x5f, 0x21, 0x76, 0xba, 0x59, 0x19, 0x98, 0xaf, 0xb9, 0xe3, 0xc8, 0x25, 0x79,
			0x50, 0x50, 0xaf, 0xc4, 0xb5, 0x3d, 0x68, 0xe4, 0x1e, 0xd9, 0x21, 0xda, 0x89, 0xde, 0x51, 0xe7,
			0xda, 0x35, 0xa2, 0x95, 0xb5, 0x9c, 0x2b, 0x8a, 0xae, 0xa4, 0x39, 0x91, 0x48, 0xd5, 0x0c, 0xff,
			0x68, 0x59, 0x6b, 0x4d, 0xcb, 0x8b, 0xc2, 0xc1, 0x1b, 0xb1, 0x84, 0xd5, 0x90, 0x56, 0x13, 0xe8,
		},
	},
	{
		Zpk: []byte{
			0x98, 0xfd, 0xfa, 0x25, 0x79, 0x90, 0xfa, 0x50, 0xd4, 0xe7, 0xc8, 0x78, 0x21, 0xa0, 0x71, 0x21,
			0x95, 0xe5, 0x85, 0x97, 0x90, 0x96, 0x73, 0xf3, 0xdf, 0xea, 0xef, 0xa4, 0x52, 0xb6, 0xd7, 0x50,
		},
		Zid: []byte{
			0x00, 0x01, 0x00, 0x00,
			0x67, 0x7c, 0x47, 0x7d, 0x2d, 0x93, 0x09, 0x7c, 0x85, 0xb1, 0x95, 0xc6, 0xf9, 0x6d, 0x84, 0xff,
			0x61, 0xf5, 0x98, 0x2c, 0x2c, 0x4f, 0xe0, 0x2d, 0x5a, 0x11, 0xfe, 0xdf, 0xb0, 0xc2, 0x90, 0x1f,
		},
		Ztld:  "000G0037FH3QTBCK15Y8BCCNRVWPV17ZC7TSGB1C9ZG2TPGHZVFV1GMG3W",
		Label: "天下無敵",
		Q: []byte{
			0xaf, 0xf0, 0xad, 0x6a, 0x44, 0x09, 0x73, 0x68, 0x42, 0x9a, 0xc4, 0x76, 0xdf, 0xa1, 0xf3, 0x4b,
			0xee, 0x4c, 0x36, 0xe7, 0x47, 0x6d, 0x07, 0xaa, 0x64, 0x63, 0xff, 0x20, 0x91, 0x5b, 0x10, 0x05,
			0xc0, 0x99, 0x1d, 0xef, 0x91, 0xfc, 0x3e, 0x10, 0x90, 0x9f, 0x87, 0x02, 0xc0, 0xbe, 0x40, 0x43,
			0x67, 0x78, 0xc7, 0x11, 0xf2, 0xca, 0x47, 0xd5, 0x5c, 0xf0, 0xb5, 0x4d, 0x23, 0x5d, 0xa9, 0x77,
		},
		Recs: []*Rec{
			{
				Expire: []byte{0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80},
				Size:   []byte{0x00, 0x10},
				Type:   []byte{0x00, 0x00, 0x00, 0x1c},
				Flags:  []byte{0x00, 0x00},
				Data:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef},
			},
			{
				Expire: []byte{0x00, 0xb0, 0x0f, 0x81, 0xb7, 0x44, 0x9b, 0x40},
				Size:   []byte{0x00, 0x06},
				Type:   []byte{0x00, 0x01, 0x00, 0x01},
				Flags:  []byte{0x80, 0x00},
				Data:   []byte{0xe6, 0x84, 0x9b, 0xe7, 0xa7, 0xb0},
			},
			{
				Expire: []byte{0x00, 0x00, 0x00, 0x01, 0x6b, 0x59, 0x71, 0x08},
				Size:   []byte{0x00, 0x0b},
				Type:   []byte{0x00, 0x00, 0x00, 0x10},
				Flags:  []byte{0x40, 0x04},
				Data:   []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64},
			},
		},
		Rdata: []byte{
			0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
			0x00, 0xb0, 0x0f, 0x81, 0xb7, 0x44, 0x9b, 0x40, 0x00, 0x06, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01,
			0xe6, 0x84, 0x9b, 0xe7, 0xa7, 0xb0, 0x00, 0x00, 0x00, 0x01, 0x6b, 0x59, 0x71, 0x08, 0x00, 0x0b,
			0x40, 0x04, 0x00, 0x00, 0x00, 0x10, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
			0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		Enc: &Enc{
			Nonce: []byte{
				0xee, 0x96, 0x33, 0xc1, 0x00, 0x00, 0x00, 0x01,
				0x6b, 0x59, 0x71, 0x08, 0x00, 0x00, 0x00, 0x01,
			},
			Expire:  []byte{0x00, 0x05, 0xdb, 0x3b, 0xcd, 0xbd, 0x61, 0x7c},
			Counter: []byte{0x00, 0x00, 0x00, 0x01},
			Key: []byte{
				0xfb, 0x3a, 0xb5, 0xde, 0x23, 0xbd, 0xda, 0xe1, 0x99, 0x7a, 0xaf, 0x7b, 0x92, 0xc2, 0xd2, 0x71,
				0x51, 0x40, 0x8b, 0x77, 0xaf, 0x7a, 0x41, 0xac, 0x79, 0x05, 0x7c, 0x4d, 0xf5, 0x38, 0x3d, 0x01,
			},
		},
		Bdata: []byte{
			0xf8, 0xc5, 0xe4, 0xba, 0xdf, 0x16, 0x49, 0xd4, 0x04, 0xda, 0x64, 0xdf, 0x7d, 0x9d, 0x28, 0x5f,
			0x40, 0x72, 0xa5, 0xf7, 0xa2, 0x54, 0x7d, 0x56, 0x74, 0x22, 0x7e, 0x9b, 0x18, 0x8e, 0xb2, 0xbb,
			0x6b, 0x34, 0x53, 0x2f, 0x61, 0xe0, 0x8f, 0xfb, 0xd5, 0xbd, 0xea, 0x37, 0x41, 0xe6, 0x09, 0x67,
			0xb6, 0x87, 0xf8, 0xd8, 0xc4, 0x4c, 0x8f, 0x6f, 0x12, 0x0a, 0x0f, 0x98, 0x0f, 0x39, 0x3b, 0x21,
			0x60, 0x40, 0x7b, 0xe1, 0x28, 0xa7, 0x4a, 0x51, 0x51, 0xd6, 0x37, 0x0b, 0xe5, 0x6a, 0x86, 0xea,
			0xe3, 0x2f, 0xdc, 0x21, 0x75, 0x96, 0xb1, 0x3f, 0x6f, 0xea, 0x3f, 0xcf, 0xea, 0x0f, 0x4d, 0xeb,
			0x88, 0x1a, 0x25, 0x45, 0x8f, 0x50, 0x5a, 0x8f, 0xcf, 0xca, 0x62, 0xd6, 0xda, 0x56, 0x07, 0x3f,
			0x49, 0x76, 0x98, 0x61, 0x34, 0x75, 0xa1, 0xad, 0x14, 0xb7, 0x87, 0x7f, 0x94, 0x55, 0xb0, 0xec,
		},
		RRblock: []byte{
			0x00, 0x00, 0x00, 0xf0, 0x00, 0x01, 0x00, 0x00, 0xa5, 0x12, 0x96, 0xdf, 0x75, 0x7e, 0xe2, 0x75,
			0xca, 0x11, 0x8d, 0x4f, 0x07, 0xfa, 0x7a, 0xae, 0x55, 0x08, 0xbc, 0xf5, 0x12, 0xaa, 0x41, 0x12,
			0x14, 0x29, 0xd4, 0xa0, 0xde, 0x9d, 0x05, 0x7e, 0x05, 0xc0, 0x95, 0x04, 0x0b, 0x10, 0xc7, 0xf8,
			0x18, 0x7a, 0xa5, 0xda, 0x12, 0x28, 0x7d, 0x1c, 0x29, 0x10, 0xff, 0x04, 0xd6, 0xf5, 0x0a, 0xf1,
			0xfa, 0x95, 0x38, 0x2e, 0x9f, 0x00, 0x7f, 0x75, 0x09, 0x8f, 0x62, 0x0d, 0x1f, 0xf7, 0xc9, 0x71,
			0x28, 0xf4, 0x0d, 0x74, 0x58, 0xa2, 0xd3, 0xc7, 0xf0, 0x48, 0xca, 0x38, 0x20, 0x06, 0x4b, 0xdd,
			0xee, 0x94, 0x13, 0xe9, 0x54, 0x8e, 0xc9, 0x94, 0x00, 0x05, 0xdb, 0x3b, 0xcd, 0xbd, 0x61, 0x7c,
			0xf8, 0xc5, 0xe4, 0xba, 0xdf, 0x16, 0x49, 0xd4, 0x04, 0xda, 0x64, 0xdf, 0x7d, 0x9d, 0x28, 0x5f,
			0x40, 0x72, 0xa5, 0xf7, 0xa2, 0x54, 0x7d, 0x56, 0x74, 0x22, 0x7e, 0x9b, 0x18, 0x8e, 0xb2, 0xbb,
			0x6b, 0x34, 0x53, 0x2f, 0x61, 0xe0, 0x8f, 0xfb, 0xd5, 0xbd, 0xea, 0x37, 0x41, 0xe6, 0x09, 0x67,
			0xb6, 0x87, 0xf8, 0xd8, 0xc4, 0x4c, 0x8f, 0x6f, 0x12, 0x0a, 0x0f, 0x98, 0x0f, 0x39, 0x3b, 0x21,
			0x60, 0x40, 0x7b, 0xe1, 0x28, 0xa7, 0x4a, 0x51, 0x51, 0xd6, 0x37, 0x0b, 0xe5, 0x6a, 0x86, 0xea,
			0xe3, 0x2f, 0xdc, 0x21, 0x75, 0x96, 0xb1, 0x3f, 0x6f, 0xea, 0x3f, 0xcf, 0xea, 0x0f, 0x4d, 0xeb,
			0x88, 0x1a, 0x25, 0x45, 0x8f, 0x50, 0x5a, 0x8f, 0xcf, 0xca, 0x62, 0xd6, 0xda, 0x56, 0x07, 0x3f,
			0x49, 0x76, 0x98, 0x61, 0x34, 0x75, 0xa1, 0xad, 0x14, 0xb7, 0x87, 0x7f, 0x94, 0x55, 0xb0, 0xec,
		},
	},
	{
		Zpk: []byte{
			0x5a, 0xf7, 0x02, 0x0e, 0xe1, 0x91, 0x60, 0x32, 0x88, 0x32, 0x35, 0x2b, 0xbc, 0x6a, 0x68, 0xa8,
			0xd7, 0x1a, 0x7c, 0xbe, 0x1b, 0x92, 0x99, 0x69, 0xa7, 0xc6, 0x6d, 0x41, 0x5a, 0x0d, 0x8f, 0x65,
		},
		Zid: []byte{
			0x00, 0x01, 0x00, 0x14,
			0x3c, 0xf4, 0xb9, 0x24, 0x03, 0x20, 0x22, 0xf0, 0xdc, 0x50, 0x58, 0x14, 0x53, 0xb8, 0x5d, 0x93,
			0xb0, 0x47, 0xb6, 0x3d, 0x44, 0x6c, 0x58, 0x45, 0xcb, 0x48, 0x44, 0x5d, 0xdb, 0x96, 0x68, 0x8f,
		},
		Ztld:  "000G051WYJWJ80S04BRDRM2R2H9VGQCKP13VCFA4DHC4BJT88HEXQ5K8HW",
		Label: "testdelegation",
		Q: []byte{
			0xab, 0xaa, 0xba, 0xc0, 0xe1, 0x24, 0x94, 0x59, 0x75, 0x98, 0x83, 0x95, 0xaa, 0xc0, 0x24, 0x1e,
			0x55, 0x59, 0xc4, 0x1c, 0x40, 0x74, 0xe2, 0x55, 0x7b, 0x9f, 0xe6, 0xd1, 0x54, 0xb6, 0x14, 0xfb,
			0xcd, 0xd4, 0x7f, 0xc7, 0xf5, 0x1d, 0x78, 0x6d, 0xc2, 0xe0, 0xb1, 0xec, 0xe7, 0x60, 0x37, 0xc0,
			0xa1, 0x57, 0x8c, 0x38, 0x4e, 0xc6, 0x1d, 0x44, 0x56, 0x36, 0xa9, 0x4e, 0x88, 0x03, 0x29, 0xe9,
		},
		Recs: []*Rec{
			{
				Expire: []byte{0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80},
				Size:   []byte{0x00, 0x20},
				Type:   []byte{0x00, 0x01, 0x00, 0x00},
				Flags:  []byte{0x00, 0x01},
				Data: []byte{
					0x21, 0xe3, 0xb3, 0x0f, 0xf9, 0x3b, 0xc6, 0xd3, 0x5a, 0xc8, 0xc6, 0xe0, 0xe1, 0x3a, 0xfd, 0xff,
					0x79, 0x4c, 0xb7, 0xb4, 0x4b, 0xbb, 0xc7, 0x48, 0xd2, 0x59, 0xd0, 0xa0, 0x28, 0x4d, 0xbe, 0x84,
				},
			},
		},
		Rdata: []byte{
			0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
			0x21, 0xe3, 0xb3, 0x0f, 0xf9, 0x3b, 0xc6, 0xd3, 0x5a, 0xc8, 0xc6, 0xe0, 0xe1, 0x3a, 0xfd, 0xff,
			0x79, 0x4c, 0xb7, 0xb4, 0x4b, 0xbb, 0xc7, 0x48, 0xd2, 0x59, 0xd0, 0xa0, 0x28, 0x4d, 0xbe, 0x84,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		Enc: &Enc{
			Nonce: []byte{
				0x98, 0x13, 0x2e, 0xa8, 0x68, 0x59, 0xd3, 0x5c,
				0x88, 0xbf, 0xd3, 0x17, 0xfa, 0x99, 0x1b, 0xcb,
			},
			Expire: []byte{0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80},
			Key: []byte{
				0x85, 0xc4, 0x29, 0xa9, 0x56, 0x7a, 0xa6, 0x33, 0x41, 0x1a, 0x96, 0x91, 0xe9, 0x09, 0x4c, 0x45,
				0x28, 0x16, 0x72, 0xbe, 0x58, 0x60, 0x34, 0xaa, 0xe4, 0xa2, 0xa2, 0xcc, 0x71, 0x61, 0x59, 0xe2,
			},
		},
		Bdata: []byte{
			0x9c, 0xc4, 0x55, 0xa1, 0x29, 0x33, 0x19, 0x43, 0x59, 0x93, 0xcb, 0x3d, 0x67, 0x17, 0x9e, 0xc0,
			0x6e, 0xa8, 0xd8, 0x89, 0x4e, 0x90, 0x4a, 0x0c, 0x35, 0xe9, 0x1c, 0x5c, 0x2f, 0xf2, 0xed, 0x93,
			0x9c, 0xc2, 0xf8, 0x30, 0x12, 0x31, 0xf4, 0x4e, 0x59, 0x2a, 0x4a, 0xc8, 0x7e, 0x49, 0x98, 0xb9,
			0x46, 0x25, 0xc6, 0x4a, 0xf5, 0x16, 0x86, 0xa2, 0xb3, 0x6a, 0x2b, 0x28, 0x92, 0xd4, 0x4f, 0x2d,
		},
		RRblock: []byte{
			0x00, 0x00, 0x00, 0xb0, 0x00, 0x01, 0x00, 0x14, 0x9b, 0xf2, 0x33, 0x19, 0x8c, 0x6d, 0x53, 0xbb,
			0xdb, 0xac, 0x49, 0x5c, 0xab, 0xd9, 0x10, 0x49, 0xa6, 0x84, 0xaf, 0x3f, 0x40, 0x51, 0xba, 0xca,
			0xb0, 0xdc, 0xf2, 0x1c, 0x8c, 0xf2, 0x7a, 0x1a, 0x44, 0xd2, 0x40, 0xd0, 0x79, 0x02, 0xf4, 0x90,
			0xb7, 0xc4, 0x3e, 0xf0, 0x07, 0x58, 0xab, 0xce, 0x88, 0x51, 0xc1, 0x8c, 0x70, 0xac, 0x6d, 0xf9,
			0x7a, 0x88, 0xf7, 0x92, 0x11, 0xcf, 0x87, 0x5f, 0x78, 0x48, 0x85, 0xca, 0x3e, 0x34, 0x9e, 0xc4,
			0xca, 0x89, 0x2b, 0x9f, 0xf0, 0x84, 0xc5, 0x35, 0x89, 0x65, 0xb8, 0xe7, 0x4a, 0x23, 0x15, 0x95,
			0x2d, 0x4c, 0x8c, 0x06, 0x52, 0x1c, 0x2f, 0x0c, 0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80,
			0x9c, 0xc4, 0x55, 0xa1, 0x29, 0x33, 0x19, 0x43, 0x59, 0x93, 0xcb, 0x3d, 0x67, 0x17, 0x9e, 0xc0,
			0x6e, 0xa8, 0xd8, 0x89, 0x4e, 0x90, 0x4a, 0x0c, 0x35, 0xe9, 0x1c, 0x5c, 0x2f, 0xf2, 0xed, 0x93,
			0x9c, 0xc2, 0xf8, 0x30, 0x12, 0x31, 0xf4, 0x4e, 0x59, 0x2a, 0x4a, 0xc8, 0x7e, 0x49, 0x98, 0xb9,
			0x46, 0x25, 0xc6, 0x4a, 0xf5, 0x16, 0x86, 0xa2, 0xb3, 0x6a, 0x2b, 0x28, 0x92, 0xd4, 0x4f, 0x2d,
		},
	},
	{
		Zpk: []byte{
			0x5a, 0xf7, 0x02, 0x0e, 0xe1, 0x91, 0x60, 0x32, 0x88, 0x32, 0x35, 0x2b, 0xbc, 0x6a, 0x68, 0xa8,
			0xd7, 0x1a, 0x7c, 0xbe, 0x1b, 0x92, 0x99, 0x69, 0xa7, 0xc6, 0x6d, 0x41, 0x5a, 0x0d, 0x8f, 0x65,
		},
		Zid: []byte{
			0x00, 0x01, 0x00, 0x14,
			0x3c, 0xf4, 0xb9, 0x24, 0x03, 0x20, 0x22, 0xf0, 0xdc, 0x50, 0x58, 0x14, 0x53, 0xb8, 0x5d, 0x93,
			0xb0, 0x47, 0xb6, 0x3d, 0x44, 0x6c, 0x58, 0x45, 0xcb, 0x48, 0x44, 0x5d, 0xdb, 0x96, 0x68, 0x8f,
		},
		Ztld:  "000G051WYJWJ80S04BRDRM2R2H9VGQCKP13VCFA4DHC4BJT88HEXQ5K8HW",
		Label: "天下無敵",
		Q: []byte{
			0xba, 0xf8, 0x21, 0x77, 0xee, 0xc0, 0x81, 0xe0, 0x74, 0xa7, 0xda, 0x47, 0xff, 0xc6, 0x48, 0x77,
			0x58, 0xfb, 0x0d, 0xf0, 0x1a, 0x6c, 0x7f, 0xbb, 0x52, 0xfc, 0x8a, 0x31, 0xbe, 0xf0, 0x29, 0xaf,
			0x74, 0xaa, 0x0d, 0xc1, 0x5a, 0xb8, 0xe2, 0xfa, 0x7a, 0x54, 0xb4, 0xf5, 0xf6, 0x37, 0xf6, 0x15,
			0x8f, 0xa7, 0xf0, 0x3c, 0x3f, 0xce, 0xbe, 0x78, 0xd3, 0xf9, 0xd6, 0x40, 0xaa, 0xc0, 0xd1, 0xed,
		},
		Recs: []*Rec{
			{
				Expire: []byte{0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80},
				Size:   []byte{0x00, 0x10},
				Type:   []byte{0x00, 0x00, 0x00, 0x1c},
				Flags:  []byte{0x00, 0x00},
				Data:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef},
			},
			{
				Expire: []byte{0x00, 0xb0, 0x0f, 0x81, 0xb7, 0x44, 0x9b, 0x40},
				Size:   []byte{0x00, 0x06},
				Type:   []byte{0x00, 0x01, 0x00, 0x01},
				Flags:  []byte{0x80, 0x00},
				Data:   []byte{0xe6, 0x84, 0x9b, 0xe7, 0xa7, 0xb0},
			},
			{
				Expire: []byte{0x00, 0x00, 0x00, 0x01, 0x6b, 0x59, 0x71, 0x08},
				Size:   []byte{0x00, 0x0b},
				Type:   []byte{0x00, 0x00, 0x00, 0x10},
				Flags:  []byte{0x40, 0x04},
				Data:   []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64},
			},
		},
		Rdata: []byte{
			0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
			0x00, 0xb0, 0x0f, 0x81, 0xb7, 0x44, 0x9b, 0x40, 0x00, 0x06, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01,
			0xe6, 0x84, 0x9b, 0xe7, 0xa7, 0xb0, 0x00, 0x00, 0x00, 0x01, 0x6b, 0x59, 0x71, 0x08, 0x00, 0x0b,
			0x40, 0x04, 0x00, 0x00, 0x00, 0x10, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
			0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		Enc: &Enc{
			Nonce: []byte{
				0xbb, 0x0d, 0x3f, 0x0f, 0xbd, 0x22, 0x42, 0x77,
				0x50, 0xda, 0x5d, 0x69, 0x12, 0x16, 0xe6, 0xc9,
			},
			Expire: []byte{0x00, 0x05, 0xdb, 0x3b, 0xcd, 0xbd, 0x77, 0x69},
			Key: []byte{
				0x3d, 0xf8, 0x05, 0xbd, 0x66, 0x87, 0xaa, 0x14, 0x20, 0x96, 0x28, 0xc2, 0x44, 0xb1, 0x11, 0x91,
				0x88, 0xc3, 0x92, 0x56, 0x37, 0xa4, 0x1e, 0x5d, 0x76, 0x49, 0x6c, 0x29, 0x45, 0xdc, 0x37, 0x7b,
			},
		},
		Bdata: []byte{
			0x6f, 0x79, 0xa9, 0xfd, 0x28, 0xbc, 0x5e, 0x38, 0x2f, 0xc9, 0x31, 0xed, 0x22, 0x93, 0x17, 0x97,
			0x32, 0x6f, 0xdd, 0x69, 0x81, 0x29, 0xfc, 0x47, 0x8a, 0x63, 0x9e, 0x90, 0x2b, 0x41, 0x10, 0x88,
			0x0a, 0x45, 0x03, 0x7c, 0x66, 0x7f, 0xf7, 0x69, 0x5f, 0x09, 0xc4, 0xa7, 0xf4, 0xf3, 0x47, 0x1a,
			0xb2, 0x36, 0x5b, 0xf3, 0xaf, 0x79, 0xe9, 0x53, 0x69, 0x7f, 0x1e, 0x35, 0xf9, 0x3b, 0xd1, 0xad,
			0x87, 0x69, 0x71, 0xce, 0x70, 0x52, 0x7a, 0x3b, 0x82, 0xc0, 0x98, 0xd2, 0x3f, 0xff, 0xd4, 0xa4,
			0x00, 0x57, 0xb6, 0x94, 0xbe, 0xc4, 0x34, 0x16, 0x4f, 0xb8, 0x3c, 0x12, 0xb1, 0xf4, 0x57, 0x0f,
			0x69, 0xa2, 0x8f, 0x3b, 0xc3, 0xb7, 0xd8, 0x38, 0xb2, 0x61, 0x9f, 0x6b, 0x8e, 0x17, 0x23, 0xba,
			0x78, 0xc4, 0xb7, 0xce, 0x19, 0xef, 0x3f, 0x39, 0x04, 0x05, 0xb6, 0x3f, 0x7c, 0xe0, 0x02, 0x16,
			0x1b, 0xdd, 0x7f, 0x5e, 0x9b, 0x36, 0x22, 0xbc, 0x1a, 0xf2, 0xd4, 0xca, 0x84, 0xfd, 0x5f, 0xc5,
		},
		RRblock: []byte{
			0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x14, 0x74, 0xf9, 0x00, 0x68, 0xf1, 0x67, 0x69, 0x53,
			0x52, 0xa8, 0xa6, 0xc2, 0xeb, 0x98, 0x48, 0x98, 0xc5, 0x3a, 0xcc, 0xa0, 0x98, 0x04, 0x70, 0xc6,
			0xc8, 0x12, 0x64, 0xcb, 0xdd, 0x78, 0xad, 0x11, 0x13, 0xb6, 0xb7, 0x83, 0x58, 0xa8, 0x8d, 0xe7,
			0x3c, 0x5d, 0x22, 0xf7, 0x3f, 0x1a, 0xd5, 0x88, 0xee, 0x6f, 0x07, 0xd1, 0x34, 0x10, 0xa2, 0xf5,
			0x15, 0xa0, 0x74, 0x87, 0x26, 0x08, 0xec, 0x02, 0xef, 0x90, 0x20, 0xfd, 0xeb, 0x42, 0x66, 0xbf,
			0x11, 0x77, 0xc7, 0xe5, 0x7e, 0x78, 0x60, 0x59, 0x97, 0x03, 0x2a, 0x3f, 0x71, 0xf7, 0x21, 0x6c,
			0x89, 0x4e, 0x07, 0x3a, 0xc7, 0x7f, 0x2a, 0x0d, 0x00, 0x05, 0xdb, 0x3b, 0xcd, 0xbd, 0x77, 0x69,
			0x6f, 0x79, 0xa9, 0xfd, 0x28, 0xbc, 0x5e, 0x38, 0x2f, 0xc9, 0x31, 0xed, 0x22, 0x93, 0x17, 0x97,
			0x32, 0x6f, 0xdd, 0x69, 0x81, 0x29, 0xfc, 0x47, 0x8a, 0x63, 0x9e, 0x90, 0x2b, 0x41, 0x10, 0x88,
			0x0a, 0x45, 0x03, 0x7c, 0x66, 0x7f, 0xf7, 0x69, 0x5f, 0x09, 0xc4, 0xa7, 0xf4, 0xf3, 0x47, 0x1a,
			0xb2, 0x36, 0x5b, 0xf3, 0xaf, 0x79, 0xe9, 0x53, 0x69, 0x7f, 0x1e, 0x35, 0xf9, 0x3b, 0xd1, 0xad,
			0x87, 0x69, 0x71, 0xce, 0x70, 0x52, 0x7a, 0x3b, 0x82, 0xc0, 0x98, 0xd2, 0x3f, 0xff, 0xd4, 0xa4,
			0x00, 0x57, 0xb6, 0x94, 0xbe, 0xc4, 0x34, 0x16, 0x4f, 0xb8, 0x3c, 0x12, 0xb1, 0xf4, 0x57, 0x0f,
			0x69, 0xa2, 0x8f, 0x3b, 0xc3, 0xb7, 0xd8, 0x38, 0xb2, 0x61, 0x9f, 0x6b, 0x8e, 0x17, 0x23, 0xba,
			0x78, 0xc4, 0xb7, 0xce, 0x19, 0xef, 0x3f, 0x39, 0x04, 0x05, 0xb6, 0x3f, 0x7c, 0xe0, 0x02, 0x16,
			0x1b, 0xdd, 0x7f, 0x5e, 0x9b, 0x36, 0x22, 0xbc, 0x1a, 0xf2, 0xd4, 0xca, 0x84, 0xfd, 0x5f, 0xc5,
		},
	},
}

func TestRecordsRFC(t *testing.T) {
	for n, tc := range tests {
		if n > 0 {
			break
		}
		fmt.Printf("Testcase #%d:\n", n)

		var ztype enums.GNSType
		rdInt(tc.Zid, &ztype)
		fmt.Printf("   ztype = %08x (%d)\n", uint32(ztype), ztype)

		sk, err := crypto.NewZonePrivate(ztype, tc.Zpk)
		if err != nil {
			t.Log("Failed: " + err.Error())
			t.Fail()
			continue
		}
		fmt.Printf("   skey = %s\n", hex.EncodeToString(sk.Bytes()))

		zkey := sk.Public()
		fmt.Printf("   zkey = %s\n", hex.EncodeToString(zkey.Bytes()))
		if !bytes.Equal(zkey.Bytes(), tc.Zid) {
			fmt.Printf("       != %s\n", hex.EncodeToString(tc.Zid))
			t.Fail()
			continue
		}

		if util.EncodeBinaryToString(tc.Zid) != tc.Ztld {
			t.Log("Failed: zTLD mismatch")
			t.Fail()
			continue
		}

		pd, _, err := zkey.Derive(tc.Label, "gns")
		if err != nil {
			t.Log("Failed: " + err.Error())
			t.Fail()
			continue
		}
		q := crypto.Hash(pd.Bytes()).Data
		fmt.Printf("   Q = %s\n", hex.EncodeToString(q))
		if !bytes.Equal(q, tc.Q) {
			fmt.Printf("    != %s\n", hex.EncodeToString(tc.Q))
			t.Log("Failed: storage key mismatch")
			t.Fail()
		}

		rs := &blocks.RecordSet{
			Count:   uint32(len(tc.Recs)),
			Records: make([]*blocks.ResourceRecord, len(tc.Recs)),
		}
		for i, rr := range tc.Recs {
			var ts uint64
			rdInt(rr.Expire, &ts)
			var size uint16
			rdInt(rr.Size, &size)
			var flags enums.GNSFlag
			rdInt(rr.Flags, &flags)
			var typ enums.GNSType
			rdInt(rr.Type, &typ)
			rs.Records[i] = &blocks.ResourceRecord{
				Expire: util.AbsoluteTime{
					Val: uint64(ts),
				},
				Size:  size,
				RType: typ,
				Flags: flags,
				Data:  rr.Data,
			}
		}
		rs.SetPadding()
		rdata := rs.RDATA()
		if !bytes.Equal(rdata, tc.Rdata) {
			fmt.Printf("   rdata = %s\n", hex.EncodeToString(rdata))
			fmt.Printf("        != %s\n", hex.EncodeToString(tc.Rdata))
			t.Log("RDATA mismatch")
			t.Fail()
			continue
		}

		expires := rs.Expire()
		var ts uint64
		rdInt(tc.Enc.Expire, &ts)
		e2 := util.AbsoluteTime{
			Val: ts,
		}
		if expires.Compare(e2) != 0 {
			t.Logf("expire: %s != %s\n", expires, e2)
			t.Fail()
		}
		skey := zkey.BlockKey(tc.Label, expires)
		if !bytes.Equal(skey[32:48], tc.Enc.Nonce) {
			fmt.Printf("nonce = %s\n", hex.EncodeToString(skey[32:48]))
			fmt.Printf("NONCE = %s\n", hex.EncodeToString(tc.Enc.Nonce))
			t.Log("NONCE mismatch")
			t.Fail()
			continue
		}
		bdata, err := zkey.Encrypt(rdata, tc.Label, expires)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bdata, tc.Bdata) {
			fmt.Printf("bdata = %s\n", hex.EncodeToString(bdata))
			fmt.Printf("BDATA = %s\n", hex.EncodeToString(tc.Bdata))
			t.Log("BDATA mismatch")
			t.Fail()
			continue
		}

		blk := blocks.NewGNSBlock().(*blocks.GNSBlock)
		blk.Prepare(enums.BLOCK_TYPE_GNS_NAMERECORD, expires)
		blk.SetData(bdata)
		dsk, _, _ := sk.Derive(tc.Label, "gns")
		blk.Sign(dsk)
		rrblock := blk.RRBLOCK()
		if !bytes.Equal(rrblock, tc.RRblock) {
			fmt.Printf("rrblock = %s\n", hex.EncodeToString(rrblock))
			fmt.Printf("RRBLOCK = %s\n", hex.EncodeToString(tc.RRblock))
			t.Log("RRblock mismatch")
			t.Fail()
			continue
		}
	}
}

func rdInt(data []byte, v any) {
	_ = binary.Read(bytes.NewReader(data), binary.BigEndian, v)
}
