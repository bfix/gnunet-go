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
	Zprv  []byte
	Zid   []byte
	Ztld  string
	Label string
	Dzprv []byte
	Dzpub []byte
	Q     []byte
	Recs  []*Rec
	Rdata []byte
	Enc   *Enc
	Bdata []byte

	RRblock []byte
}

var tests = []*TestCase{
	// Testcase #1
	{
		Zprv: []byte{
			0x50, 0xd7, 0xb6, 0x52, 0xa4, 0xef, 0xea, 0xdf, 0xf3, 0x73, 0x96, 0x90, 0x97, 0x85, 0xe5, 0x95,
			0x21, 0x71, 0xa0, 0x21, 0x78, 0xc8, 0xe7, 0xd4, 0x50, 0xfa, 0x90, 0x79, 0x25, 0xfa, 0xfd, 0x98,
		},
		Zid: []byte{
			0x00, 0x01, 0x00, 0x00,
			0x67, 0x7c, 0x47, 0x7d, 0x2d, 0x93, 0x09, 0x7c, 0x85, 0xb1, 0x95, 0xc6, 0xf9, 0x6d, 0x84, 0xff,
			0x61, 0xf5, 0x98, 0x2c, 0x2c, 0x4f, 0xe0, 0x2d, 0x5a, 0x11, 0xfe, 0xdf, 0xb0, 0xc2, 0x90, 0x1f,
		},
		Ztld: "000G0037FH3QTBCK15Y8BCCNRVWPV17ZC7TSGB1C9ZG2TPGHZVFV1GMG3W",
		Dzprv: []byte{
			0x0a, 0x4c, 0x5e, 0x0f, 0x00, 0x63, 0xdf, 0xce,
			0xdb, 0xc8, 0xc7, 0xf2, 0xb2, 0x2c, 0x03, 0x0c,
			0x86, 0x28, 0xb2, 0xc2, 0xcb, 0xac, 0x9f, 0xa7,
			0x29, 0xaa, 0xe6, 0x1f, 0x89, 0xdb, 0x3e, 0x9c,
		},
		Dzpub: []byte{
			0x18, 0x2b, 0xb6, 0x36, 0xed, 0xa7, 0x9f, 0x79,
			0x57, 0x11, 0xbc, 0x27, 0x08, 0xad, 0xbb, 0x24,
			0x2a, 0x60, 0x44, 0x6a, 0xd3, 0xc3, 0x08, 0x03,
			0x12, 0x1d, 0x03, 0xd3, 0x48, 0xb7, 0xce, 0xb6,
		},
		Label: "testdelegation",
		Q: []byte{
			0x4a, 0xdc, 0x67, 0xc5, 0xec, 0xee, 0x9f, 0x76, 0x98, 0x6a, 0xbd, 0x71, 0xc2, 0x22, 0x4a, 0x3d,
			0xce, 0x2e, 0x91, 0x70, 0x26, 0xc9, 0xa0, 0x9d, 0xfd, 0x44, 0xce, 0xf3, 0xd2, 0x0f, 0x55, 0xa2,
			0x73, 0x32, 0x72, 0x5a, 0x6c, 0x8a, 0xfb, 0xbb, 0xb0, 0xf7, 0xec, 0x9a, 0xf1, 0xcc, 0x42, 0x64,
			0x12, 0x99, 0x40, 0x6b, 0x04, 0xfd, 0x9b, 0x5b, 0x57, 0x91, 0xf8, 0x6c, 0x4b, 0x08, 0xd5, 0xf4,
		},
		Recs: []*Rec{
			{
				Expire: []byte{0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80},
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
			0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
			0x21, 0xe3, 0xb3, 0x0f, 0xf9, 0x3b, 0xc6, 0xd3, 0x5a, 0xc8, 0xc6, 0xe0, 0xe1, 0x3a, 0xfd, 0xff,
			0x79, 0x4c, 0xb7, 0xb4, 0x4b, 0xbb, 0xc7, 0x48, 0xd2, 0x59, 0xd0, 0xa0, 0x28, 0x4d, 0xbe, 0x84,
		},
		Enc: &Enc{
			Nonce:   []byte{0xe9, 0x0a, 0x00, 0x61},
			Expire:  []byte{0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80},
			Counter: []byte{0x00, 0x00, 0x00, 0x01},
			Key: []byte{
				0x86, 0x4e, 0x71, 0x38, 0xea, 0xe7, 0xfd, 0x91, 0xa3, 0x01, 0x36, 0x89, 0x9c, 0x13, 0x2b, 0x23,
				0xac, 0xeb, 0xdb, 0x2c, 0xef, 0x43, 0xcb, 0x19, 0xf6, 0xbf, 0x55, 0xb6, 0x7d, 0xb9, 0xb3, 0xb3,
			},
		},
		Bdata: []byte{
			0x0c, 0x1e, 0xda, 0x5c, 0xc0, 0x94, 0xa1, 0xc7, 0xa8, 0x88, 0x64, 0x9d, 0x25, 0xfa, 0xee, 0xbd,
			0x60, 0xda, 0xe6, 0x07, 0x3d, 0x57, 0xd8, 0xae, 0x8d, 0x45, 0x5f, 0x4f, 0x13, 0x92, 0xc0, 0x74,
			0xe2, 0x6a, 0xc6, 0x69, 0xbd, 0xee, 0xc2, 0x34, 0x62, 0xb9, 0x62, 0x95, 0x2c, 0xc6, 0xe9, 0xeb,
		},

		RRblock: []byte{
			0x00, 0x00, 0x00, 0xa0, 0x00, 0x01, 0x00, 0x00, 0x18, 0x2b, 0xb6, 0x36, 0xed, 0xa7, 0x9f, 0x79,
			0x57, 0x11, 0xbc, 0x27, 0x08, 0xad, 0xbb, 0x24, 0x2a, 0x60, 0x44, 0x6a, 0xd3, 0xc3, 0x08, 0x03,
			0x12, 0x1d, 0x03, 0xd3, 0x48, 0xb7, 0xce, 0xb6, 0x0a, 0xd1, 0x0b, 0xc1, 0x3b, 0x40, 0x3b, 0x5b,
			0x25, 0x61, 0x26, 0xb2, 0x14, 0x5a, 0x6f, 0x60, 0xc5, 0x14, 0xf9, 0x51, 0xff, 0xa7, 0x66, 0xf7,
			0xa3, 0xfd, 0x4b, 0xac, 0x4a, 0x4e, 0x19, 0x90, 0x05, 0x5c, 0xb8, 0x7e, 0x8d, 0x1b, 0xfd, 0x19,
			0xaa, 0x09, 0xa4, 0x29, 0xf7, 0x29, 0xe9, 0xf5, 0xc6, 0xee, 0xc2, 0x47, 0x0a, 0xce, 0xe2, 0x22,
			0x07, 0x59, 0xe9, 0xe3, 0x6c, 0x88, 0x6f, 0x35, 0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80,
			0x0c, 0x1e, 0xda, 0x5c, 0xc0, 0x94, 0xa1, 0xc7, 0xa8, 0x88, 0x64, 0x9d, 0x25, 0xfa, 0xee, 0xbd,
			0x60, 0xda, 0xe6, 0x07, 0x3d, 0x57, 0xd8, 0xae, 0x8d, 0x45, 0x5f, 0x4f, 0x13, 0x92, 0xc0, 0x74,
			0xe2, 0x6a, 0xc6, 0x69, 0xbd, 0xee, 0xc2, 0x34, 0x62, 0xb9, 0x62, 0x95, 0x2c, 0xc6, 0xe9, 0xeb,
		},
	},
	// Testcase #2
	{
		Zprv: []byte{
			0x50, 0xd7, 0xb6, 0x52, 0xa4, 0xef, 0xea, 0xdf, 0xf3, 0x73, 0x96, 0x90, 0x97, 0x85, 0xe5, 0x95,
			0x21, 0x71, 0xa0, 0x21, 0x78, 0xc8, 0xe7, 0xd4, 0x50, 0xfa, 0x90, 0x79, 0x25, 0xfa, 0xfd, 0x98,
		},
		Zid: []byte{
			0x00, 0x01, 0x00, 0x00,
			0x67, 0x7c, 0x47, 0x7d, 0x2d, 0x93, 0x09, 0x7c, 0x85, 0xb1, 0x95, 0xc6, 0xf9, 0x6d, 0x84, 0xff,
			0x61, 0xf5, 0x98, 0x2c, 0x2c, 0x4f, 0xe0, 0x2d, 0x5a, 0x11, 0xfe, 0xdf, 0xb0, 0xc2, 0x90, 0x1f,
		},
		Ztld:  "000G0037FH3QTBCK15Y8BCCNRVWPV17ZC7TSGB1C9ZG2TPGHZVFV1GMG3W",
		Label: "天下無敵",
		Dzprv: []byte{
			0x0a, 0xbe, 0x56, 0xd6, 0x80, 0x68, 0xab, 0x40, 0xe1, 0x44, 0x79, 0x0c, 0xde, 0x9a, 0xcf, 0x4d,
			0x78, 0x7f, 0x2d, 0x3c, 0x63, 0xb8, 0x53, 0x05, 0x74, 0x6e, 0x68, 0x03, 0x32, 0x15, 0xf2, 0xab,
		},
		Dzpub: []byte{
			0xa5, 0x12, 0x96, 0xdf, 0x75, 0x7e, 0xe2, 0x75, 0xca, 0x11, 0x8d, 0x4f, 0x07, 0xfa, 0x7a, 0xae,
			0x55, 0x08, 0xbc, 0xf5, 0x12, 0xaa, 0x41, 0x12, 0x14, 0x29, 0xd4, 0xa0, 0xde, 0x9d, 0x05, 0x7e,
		},
		Q: []byte{
			0xaf, 0xf0, 0xad, 0x6a, 0x44, 0x09, 0x73, 0x68, 0x42, 0x9a, 0xc4, 0x76, 0xdf, 0xa1, 0xf3, 0x4b,
			0xee, 0x4c, 0x36, 0xe7, 0x47, 0x6d, 0x07, 0xaa, 0x64, 0x63, 0xff, 0x20, 0x91, 0x5b, 0x10, 0x05,
			0xc0, 0x99, 0x1d, 0xef, 0x91, 0xfc, 0x3e, 0x10, 0x90, 0x9f, 0x87, 0x02, 0xc0, 0xbe, 0x40, 0x43,
			0x67, 0x78, 0xc7, 0x11, 0xf2, 0xca, 0x47, 0xd5, 0x5c, 0xf0, 0xb5, 0x4d, 0x23, 0x5d, 0xa9, 0x77,
		},
		Recs: []*Rec{
			{
				Expire: []byte{0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80},
				Size:   []byte{0x00, 0x10},
				Type:   []byte{0x00, 0x00, 0x00, 0x1c},
				Flags:  []byte{0x00, 0x00},
				Data:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef},
			},
			{
				Expire: []byte{0x00, 0x3f, 0xf2, 0xab, 0x2a, 0x9c, 0x7f, 0x40},
				Size:   []byte{0x00, 0x06},
				Type:   []byte{0x00, 0x01, 0x00, 0x01},
				Flags:  []byte{0x00, 0x00},
				Data:   []byte{0xe6, 0x84, 0x9b, 0xe7, 0xa7, 0xb0},
			},
			{
				Expire: []byte{0x00, 0x28, 0xbb, 0x14, 0xd5, 0xca, 0xbd, 0x40},
				Size:   []byte{0x00, 0x0b},
				Type:   []byte{0x00, 0x00, 0x00, 0x10},
				Flags:  []byte{0x00, 0x04},
				Data:   []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64},
			},
		},
		Rdata: []byte{
			0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
			0x00, 0x3f, 0xf2, 0xab, 0x2a, 0x9c, 0x7f, 0x40, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
			0xe6, 0x84, 0x9b, 0xe7, 0xa7, 0xb0, 0x00, 0x28, 0xbb, 0x14, 0xd5, 0xca, 0xbd, 0x40, 0x00, 0x0b,
			0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
			0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		Enc: &Enc{
			Nonce:   []byte{0xee, 0x96, 0x33, 0xc1},
			Expire:  []byte{0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80},
			Counter: []byte{0x00, 0x00, 0x00, 0x01},
			Key: []byte{
				0xfb, 0x3a, 0xb5, 0xde, 0x23, 0xbd, 0xda, 0xe1, 0x99, 0x7a, 0xaf, 0x7b, 0x92, 0xc2, 0xd2, 0x71,
				0x51, 0x40, 0x8b, 0x77, 0xaf, 0x7a, 0x41, 0xac, 0x79, 0x05, 0x7c, 0x4d, 0xf5, 0x38, 0x3d, 0x01,
			},
		},
		Bdata: []byte{
			0xd8, 0xc2, 0x8d, 0x2f, 0xd6, 0x96, 0x7d, 0x1a, 0xb7, 0x22, 0x53, 0xf2, 0x10, 0x98, 0xb8, 0x14,
			0xa4, 0x10, 0xbe, 0x1f, 0x59, 0x98, 0xde, 0x03, 0xf5, 0x8f, 0x7e, 0x7c, 0xdb, 0x7f, 0x08, 0xa6,
			0x16, 0x51, 0xbe, 0x4c, 0x75, 0xfb, 0x2e, 0x61, 0xdf, 0x15, 0x30, 0x44, 0x0b, 0xd7, 0x47, 0xdc,
			0xf0, 0xd7, 0x10, 0x4f, 0x6b, 0x8d, 0x24, 0xc2, 0xac, 0x9c, 0xeb, 0xc0, 0x38, 0x6f, 0xe8, 0x29,
			0x05, 0x25, 0xd2, 0xa6, 0xd0, 0xf8, 0x84, 0x42, 0x67, 0xa1, 0x57, 0x0e, 0x8e, 0x29, 0x4d, 0xc9,
			0x3a, 0x31, 0x9f, 0xcf, 0xc0, 0x3e, 0xa2, 0x70, 0x17, 0xd6, 0xfd, 0xa3, 0x47, 0xb4, 0xa7, 0x94,
			0x97, 0xd7, 0xf6, 0xb1, 0x42, 0x2d, 0x4e, 0xdd, 0x82, 0x1c, 0x19, 0x93, 0x4e, 0x96, 0xc1, 0xaa,
			0x87, 0x76, 0x57, 0x25, 0xd4, 0x94, 0xc7, 0x64, 0xb1, 0x55, 0xdc, 0x6d, 0x13, 0x26, 0x91, 0x74,
		},
		RRblock: []byte{
			0x00, 0x00, 0x00, 0xf0, 0x00, 0x01, 0x00, 0x00, 0xa5, 0x12, 0x96, 0xdf, 0x75, 0x7e, 0xe2, 0x75,
			0xca, 0x11, 0x8d, 0x4f, 0x07, 0xfa, 0x7a, 0xae, 0x55, 0x08, 0xbc, 0xf5, 0x12, 0xaa, 0x41, 0x12,
			0x14, 0x29, 0xd4, 0xa0, 0xde, 0x9d, 0x05, 0x7e, 0x08, 0x2f, 0xfa, 0xa1, 0x83, 0x71, 0xdc, 0x82,
			0x91, 0x9d, 0x5e, 0xd4, 0xd4, 0x91, 0xae, 0x65, 0xcd, 0x09, 0x2f, 0x61, 0xa7, 0x26, 0xa9, 0xee,
			0x29, 0xb2, 0x1a, 0xfe, 0x5f, 0xdd, 0x96, 0x29, 0x0c, 0xfc, 0xb9, 0x12, 0xad, 0xe6, 0x7f, 0x3a,
			0x75, 0x92, 0x4f, 0x17, 0x4d, 0xb0, 0x34, 0xdf, 0x00, 0x70, 0xfb, 0xf8, 0x13, 0x96, 0xef, 0xee,
			0x19, 0xb9, 0xcd, 0x80, 0x21, 0x06, 0x3e, 0x35, 0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80,
			0xd8, 0xc2, 0x8d, 0x2f, 0xd6, 0x96, 0x7d, 0x1a, 0xb7, 0x22, 0x53, 0xf2, 0x10, 0x98, 0xb8, 0x14,
			0xa4, 0x10, 0xbe, 0x1f, 0x59, 0x98, 0xde, 0x03, 0xf5, 0x8f, 0x7e, 0x7c, 0xdb, 0x7f, 0x08, 0xa6,
			0x16, 0x51, 0xbe, 0x4c, 0x75, 0xfb, 0x2e, 0x61, 0xdf, 0x15, 0x30, 0x44, 0x0b, 0xd7, 0x47, 0xdc,
			0xf0, 0xd7, 0x10, 0x4f, 0x6b, 0x8d, 0x24, 0xc2, 0xac, 0x9c, 0xeb, 0xc0, 0x38, 0x6f, 0xe8, 0x29,
			0x05, 0x25, 0xd2, 0xa6, 0xd0, 0xf8, 0x84, 0x42, 0x67, 0xa1, 0x57, 0x0e, 0x8e, 0x29, 0x4d, 0xc9,
			0x3a, 0x31, 0x9f, 0xcf, 0xc0, 0x3e, 0xa2, 0x70, 0x17, 0xd6, 0xfd, 0xa3, 0x47, 0xb4, 0xa7, 0x94,
			0x97, 0xd7, 0xf6, 0xb1, 0x42, 0x2d, 0x4e, 0xdd, 0x82, 0x1c, 0x19, 0x93, 0x4e, 0x96, 0xc1, 0xaa,
			0x87, 0x76, 0x57, 0x25, 0xd4, 0x94, 0xc7, 0x64, 0xb1, 0x55, 0xdc, 0x6d, 0x13, 0x26, 0x91, 0x74,
		},
	},
	// Testcase #3
	{
		Zprv: []byte{
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
		Dzprv: []byte{
			0x3b, 0x1b, 0x29, 0xd4, 0x23, 0x0b, 0x10, 0xa8, 0xec, 0x4d, 0xa3, 0xc8, 0x6e, 0xdb, 0x88, 0xea,
			0xcd, 0x54, 0x08, 0x5c, 0x1d, 0xdb, 0x63, 0xf7, 0xa9, 0xd7, 0x3f, 0x7c, 0xcb, 0x2f, 0xc3, 0x98,
		},
		Dzpub: []byte{
			0x9b, 0xf2, 0x33, 0x19, 0x8c, 0x6d, 0x53, 0xbb, 0xdb, 0xac, 0x49, 0x5c, 0xab, 0xd9, 0x10, 0x49,
			0xa6, 0x84, 0xaf, 0x3f, 0x40, 0x51, 0xba, 0xca, 0xb0, 0xdc, 0xf2, 0x1c, 0x8c, 0xf2, 0x7a, 0x1a,
		},
		Q: []byte{
			0xab, 0xaa, 0xba, 0xc0, 0xe1, 0x24, 0x94, 0x59, 0x75, 0x98, 0x83, 0x95, 0xaa, 0xc0, 0x24, 0x1e,
			0x55, 0x59, 0xc4, 0x1c, 0x40, 0x74, 0xe2, 0x55, 0x7b, 0x9f, 0xe6, 0xd1, 0x54, 0xb6, 0x14, 0xfb,
			0xcd, 0xd4, 0x7f, 0xc7, 0xf5, 0x1d, 0x78, 0x6d, 0xc2, 0xe0, 0xb1, 0xec, 0xe7, 0x60, 0x37, 0xc0,
			0xa1, 0x57, 0x8c, 0x38, 0x4e, 0xc6, 0x1d, 0x44, 0x56, 0x36, 0xa9, 0x4e, 0x88, 0x03, 0x29, 0xe9,
		},
		Recs: []*Rec{
			{
				Expire: []byte{0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80},
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
			0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
			0x21, 0xe3, 0xb3, 0x0f, 0xf9, 0x3b, 0xc6, 0xd3, 0x5a, 0xc8, 0xc6, 0xe0, 0xe1, 0x3a, 0xfd, 0xff,
			0x79, 0x4c, 0xb7, 0xb4, 0x4b, 0xbb, 0xc7, 0x48, 0xd2, 0x59, 0xd0, 0xa0, 0x28, 0x4d, 0xbe, 0x84,
		},
		Enc: &Enc{
			Nonce: []byte{
				0x98, 0x13, 0x2e, 0xa8, 0x68, 0x59, 0xd3, 0x5c, 0x88, 0xbf, 0xd3, 0x17, 0xfa, 0x99, 0x1b, 0xcb,
			},
			Expire: []byte{0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80},
			Key: []byte{
				0x85, 0xc4, 0x29, 0xa9, 0x56, 0x7a, 0xa6, 0x33, 0x41, 0x1a, 0x96, 0x91, 0xe9, 0x09, 0x4c, 0x45,
				0x28, 0x16, 0x72, 0xbe, 0x58, 0x60, 0x34, 0xaa, 0xe4, 0xa2, 0xa2, 0xcc, 0x71, 0x61, 0x59, 0xe2,
			},
		},
		Bdata: []byte{
			0x57, 0x7c, 0xc6, 0xc9, 0x5a, 0x14, 0xe7, 0x04, 0x09, 0xf2, 0x0b, 0x01, 0x67, 0xe6, 0x36, 0xd0,
			0x10, 0x80, 0x7c, 0x4f, 0x00, 0x37, 0x2d, 0x69, 0x8c, 0x82, 0x6b, 0xd9, 0x2b, 0xc2, 0x2b, 0xd6,
			0xbb, 0x45, 0xe5, 0x27, 0x7c, 0x01, 0x88, 0x1d, 0x6a, 0x43, 0x60, 0x68, 0xe4, 0xdd, 0xf1, 0xc6,
			0xb7, 0xd1, 0x41, 0x6f, 0xaf, 0xa6, 0x69, 0x7c, 0x25, 0xed, 0xd9, 0xea, 0xe9, 0x91, 0x67, 0xc3,
		},
		RRblock: []byte{
			0x00, 0x00, 0x00, 0xb0, 0x00, 0x01, 0x00, 0x14, 0x9b, 0xf2, 0x33, 0x19, 0x8c, 0x6d, 0x53, 0xbb,
			0xdb, 0xac, 0x49, 0x5c, 0xab, 0xd9, 0x10, 0x49, 0xa6, 0x84, 0xaf, 0x3f, 0x40, 0x51, 0xba, 0xca,
			0xb0, 0xdc, 0xf2, 0x1c, 0x8c, 0xf2, 0x7a, 0x1a, 0x9f, 0x56, 0xa8, 0x86, 0xea, 0x73, 0x9d, 0x59,
			0x17, 0x50, 0x8f, 0x9b, 0x75, 0x56, 0x39, 0xf3, 0xa9, 0xac, 0xfa, 0xed, 0xed, 0xca, 0x7f, 0xbf,
			0xa7, 0x94, 0xb1, 0x92, 0xe0, 0x8b, 0xf9, 0xed, 0x4c, 0x7e, 0xc8, 0x59, 0x4c, 0x9f, 0x7b, 0x4e,
			0x19, 0x77, 0x4f, 0xf8, 0x38, 0xec, 0x38, 0x7a, 0x8f, 0x34, 0x23, 0xda, 0xac, 0x44, 0x9f, 0x59,
			0xdb, 0x4e, 0x83, 0x94, 0x3f, 0x90, 0x72, 0x00, 0x00, 0x1c, 0xee, 0x8c, 0x10, 0xe2, 0x59, 0x80,
			0x57, 0x7c, 0xc6, 0xc9, 0x5a, 0x14, 0xe7, 0x04, 0x09, 0xf2, 0x0b, 0x01, 0x67, 0xe6, 0x36, 0xd0,
			0x10, 0x80, 0x7c, 0x4f, 0x00, 0x37, 0x2d, 0x69, 0x8c, 0x82, 0x6b, 0xd9, 0x2b, 0xc2, 0x2b, 0xd6,
			0xbb, 0x45, 0xe5, 0x27, 0x7c, 0x01, 0x88, 0x1d, 0x6a, 0x43, 0x60, 0x68, 0xe4, 0xdd, 0xf1, 0xc6,
			0xb7, 0xd1, 0x41, 0x6f, 0xaf, 0xa6, 0x69, 0x7c, 0x25, 0xed, 0xd9, 0xea, 0xe9, 0x91, 0x67, 0xc3,
		},
	},
	// Testcase #4
	{
		Zprv: []byte{
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
		Dzprv: []byte{
			0x17, 0xc0, 0x68, 0xa6, 0xc3, 0xf7, 0x20, 0xde, 0x0e, 0x1b, 0x69, 0xff, 0x3f, 0x53, 0xe0, 0x5d,
			0x3f, 0xe5, 0xc5, 0xb0, 0x51, 0x25, 0x7a, 0x89, 0xa6, 0x3c, 0x1a, 0xd3, 0x5a, 0xc4, 0x35, 0x58,
		},
		Dzpub: []byte{
			0x74, 0xf9, 0x00, 0x68, 0xf1, 0x67, 0x69, 0x53, 0x52, 0xa8, 0xa6, 0xc2, 0xeb, 0x98, 0x48, 0x98,
			0xc5, 0x3a, 0xcc, 0xa0, 0x98, 0x04, 0x70, 0xc6, 0xc8, 0x12, 0x64, 0xcb, 0xdd, 0x78, 0xad, 0x11,
		},
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
				Expire: []byte{0x00, 0x98, 0xd7, 0xff, 0x80, 0x4a, 0x39, 0x40},
				Size:   []byte{0x00, 0x0b},
				Type:   []byte{0x00, 0x00, 0x00, 0x10},
				Flags:  []byte{0x00, 0x04},
				Data:   []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64},
			},
		},
		Rdata: []byte{
			0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
			0x00, 0xb0, 0x0f, 0x81, 0xb7, 0x44, 0x9b, 0x40, 0x00, 0x06, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01,
			0xe6, 0x84, 0x9b, 0xe7, 0xa7, 0xb0, 0x00, 0x98, 0xd7, 0xff, 0x80, 0x4a, 0x39, 0x40, 0x00, 0x0b,
			0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
			0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		Enc: &Enc{
			Nonce: []byte{
				0xbb, 0x0d, 0x3f, 0x0f, 0xbd, 0x22, 0x42, 0x77,
				0x50, 0xda, 0x5d, 0x69, 0x12, 0x16, 0xe6, 0xc9,
			},
			Expire: []byte{0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80},
			Key: []byte{
				0x3d, 0xf8, 0x05, 0xbd, 0x66, 0x87, 0xaa, 0x14, 0x20, 0x96, 0x28, 0xc2, 0x44, 0xb1, 0x11, 0x91,
				0x88, 0xc3, 0x92, 0x56, 0x37, 0xa4, 0x1e, 0x5d, 0x76, 0x49, 0x6c, 0x29, 0x45, 0xdc, 0x37, 0x7b,
			},
		},
		Bdata: []byte{
			0x70, 0x2a, 0x19, 0x6f, 0x58, 0x2b, 0x72, 0x94, 0x77, 0x71, 0x98, 0xd0, 0xa8, 0xab, 0x30, 0x09,
			0xef, 0xca, 0xb8, 0x15, 0xbe, 0x77, 0xa7, 0x5c, 0x68, 0xc8, 0x00, 0xaa, 0x9f, 0xc2, 0x58, 0x8a,
			0xe9, 0xd7, 0xc7, 0x14, 0x56, 0x54, 0xc4, 0x41, 0xeb, 0x2e, 0x31, 0x88, 0xdb, 0x3d, 0xce, 0xcd,
			0xf3, 0x33, 0x33, 0x25, 0x64, 0xb6, 0xdd, 0xd3, 0xf0, 0x37, 0xa6, 0x78, 0xdd, 0xb7, 0x42, 0x27,
			0x79, 0xaa, 0x89, 0x09, 0xd7, 0x59, 0x29, 0x97, 0x02, 0x1e, 0x5f, 0x7a, 0x43, 0xfa, 0x9c, 0xbc,
			0x73, 0xe4, 0x17, 0x86, 0x5b, 0xec, 0xae, 0x97, 0xdf, 0xc5, 0x26, 0x0f, 0xcc, 0xf5, 0x3c, 0xae,
			0x3f, 0xb1, 0x9b, 0xf1, 0x18, 0x93, 0x17, 0xde, 0x2f, 0xd9, 0xe0, 0x1a, 0x73, 0xea, 0x8e, 0x48,
			0x99, 0xb4, 0x54, 0xd6, 0x73, 0x4c, 0x92, 0xb7, 0x42, 0x5a, 0x8b, 0x87, 0x16, 0x1f, 0xd7, 0x38,
			0x21, 0xc9, 0x58, 0x38, 0x41, 0x86, 0x1d, 0x4d, 0x5a, 0xe8, 0x02, 0xc4, 0x14, 0x14, 0xba, 0x04,
		},
		RRblock: []byte{
			0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x14, 0x74, 0xf9, 0x00, 0x68, 0xf1, 0x67, 0x69, 0x53,
			0x52, 0xa8, 0xa6, 0xc2, 0xeb, 0x98, 0x48, 0x98, 0xc5, 0x3a, 0xcc, 0xa0, 0x98, 0x04, 0x70, 0xc6,
			0xc8, 0x12, 0x64, 0xcb, 0xdd, 0x78, 0xad, 0x11, 0x84, 0x61, 0x91, 0x1b, 0x40, 0x65, 0xc1, 0x08,
			0xc6, 0x5d, 0x75, 0x0a, 0x60, 0xd4, 0x32, 0xa3, 0x13, 0x38, 0xb2, 0x02, 0x6c, 0x35, 0x8c, 0x2d,
			0x62, 0x15, 0xe4, 0xa9, 0x0d, 0x48, 0xf1, 0x8c, 0xf2, 0xcf, 0xb1, 0x8d, 0x3d, 0x11, 0x10, 0x41,
			0xcc, 0x0e, 0xee, 0x64, 0x9c, 0xd9, 0x08, 0xb8, 0x28, 0x0e, 0x44, 0x39, 0x3f, 0x4e, 0xbd, 0x98,
			0x7a, 0xd0, 0x2a, 0xb8, 0x4a, 0x8c, 0x61, 0x06, 0x00, 0x08, 0xc0, 0x6f, 0xb9, 0x28, 0x15, 0x80,
			0x70, 0x2a, 0x19, 0x6f, 0x58, 0x2b, 0x72, 0x94, 0x77, 0x71, 0x98, 0xd0, 0xa8, 0xab, 0x30, 0x09,
			0xef, 0xca, 0xb8, 0x15, 0xbe, 0x77, 0xa7, 0x5c, 0x68, 0xc8, 0x00, 0xaa, 0x9f, 0xc2, 0x58, 0x8a,
			0xe9, 0xd7, 0xc7, 0x14, 0x56, 0x54, 0xc4, 0x41, 0xeb, 0x2e, 0x31, 0x88, 0xdb, 0x3d, 0xce, 0xcd,
			0xf3, 0x33, 0x33, 0x25, 0x64, 0xb6, 0xdd, 0xd3, 0xf0, 0x37, 0xa6, 0x78, 0xdd, 0xb7, 0x42, 0x27,
			0x79, 0xaa, 0x89, 0x09, 0xd7, 0x59, 0x29, 0x97, 0x02, 0x1e, 0x5f, 0x7a, 0x43, 0xfa, 0x9c, 0xbc,
			0x73, 0xe4, 0x17, 0x86, 0x5b, 0xec, 0xae, 0x97, 0xdf, 0xc5, 0x26, 0x0f, 0xcc, 0xf5, 0x3c, 0xae,
			0x3f, 0xb1, 0x9b, 0xf1, 0x18, 0x93, 0x17, 0xde, 0x2f, 0xd9, 0xe0, 0x1a, 0x73, 0xea, 0x8e, 0x48,
			0x99, 0xb4, 0x54, 0xd6, 0x73, 0x4c, 0x92, 0xb7, 0x42, 0x5a, 0x8b, 0x87, 0x16, 0x1f, 0xd7, 0x38,
			0x21, 0xc9, 0x58, 0x38, 0x41, 0x86, 0x1d, 0x4d, 0x5a, 0xe8, 0x02, 0xc4, 0x14, 0x14, 0xba, 0x04,
		},
	},
}
