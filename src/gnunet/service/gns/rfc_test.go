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
	"strings"
	"testing"

	"github.com/bfix/gospel/math"
)

func TestRFCDump(t *testing.T) {
	for _, tc := range tests {
		var ztype enums.GNSType
		rdInt(tc.Zid, &ztype)

		endian := ""
		if ztype == enums.GNS_TYPE_PKEY {
			endian = ", big-endian"
		}
		fmt.Printf("Zone private key (d%s):\n", endian)
		dumpHex("    ", tc.Zprv)

		fmt.Println("\n\nZone identifier {")
		dumpHex("    ZTYPE: ", tc.Zid[:4])
		dumpType(tc.Zid[:4])
		fmt.Println()
		dumpHex("    ZKEY:  ", tc.Zid[4:])
		fmt.Println("\n} --> zTLD:")
		fmt.Printf("    \"%s\"\n", util.EncodeBinaryToString(tc.Zid))

		fmt.Println("\nLabel:")
		dumpHex("    ", []byte(tc.Label))
		fmt.Println()
		dumpTxt("    ", tc.Label)

		fmt.Println("\n\nStorage key (q):")
		dumpHex("    ", tc.Q)
		fmt.Println()

		for i, rr := range tc.Recs {
			fmt.Printf("\nRecord #%d {\n", i+1)

			dumpHex("    Expire: ", rr.Expire)
			dumpTime(rr.Expire)
			fmt.Println()

			dumpHex("    Size:   ", rr.Size)
			dumpSize(rr.Size)
			fmt.Println()

			dumpHex("    Flags:  ", rr.Flags)
			dumpFlags(rr.Flags)
			fmt.Println()

			dumpHex("    Type:   ", rr.Type)
			dumpType(rr.Type)
			fmt.Println()

			dumpHex("    Data:   ", rr.Data)
			fmt.Println()
		}

		fmt.Println("}\n\nRDATA:")
		dumpHex("    ", tc.Rdata)

		fmt.Println("\n\nEncryption spec {")
		dumpHex("    Nonce:   ", tc.Enc.Nonce)
		fmt.Println()
		dumpHex("    Expire:  ", tc.Enc.Expire)
		dumpTime(tc.Enc.Expire)
		fmt.Println()
		dumpHex("    Key (k): ", tc.Enc.Key)
		fmt.Println("\n}\nBDATA:")
		dumpHex("    ", tc.Bdata)
		fmt.Println("\n\nRRBLOCK:")
		dumpHex("    ", tc.RRblock)
		fmt.Printf("\n\n----------------\n\n\n")
	}
}

func TestRecordsRFC(t *testing.T) {
	for n, tc := range tests {
		fmt.Printf("Testcase #%d:\n", n+1)

		// Zonekey type
		var ztype enums.GNSType
		rdInt(tc.Zid, &ztype)
		fmt.Printf("   ztype = %08x (%d)\n", uint32(ztype), ztype)

		// generate private zone key
		zprv, err := crypto.NewZonePrivate(ztype, tc.Zprv)
		if err != nil {
			t.Log("Failed: " + err.Error())
			t.Fail()
			continue
		}
		fmt.Printf("   zprv = %s\n", hex.EncodeToString(zprv.Bytes()[32:]))

		// generate zone key (public)
		zkey := zprv.Public()
		zkb := zkey.Bytes()
		fmt.Printf("   zkey = %s\n", hex.EncodeToString(zkb))
		if !bytes.Equal(zkb, tc.Zid) {
			fmt.Printf("       != %s\n", hex.EncodeToString(tc.Zid))
			t.Fail()
			continue
		}

		// check zone identifier
		if util.EncodeBinaryToString(tc.Zid) != tc.Ztld {
			t.Log("Failed: zTLD mismatch")
			t.Fail()
			continue
		}

		// derive zone keys for given label
		dzprv, _, err := zprv.Derive(tc.Label, blocks.GNSContext)
		if err != nil {
			t.Log("Failed dzprv: " + err.Error())
			t.Fail()
			continue
		}
		fmt.Printf("   dzprv = %s\n", hex.EncodeToString(dzprv.Bytes()[32:]))
		d1 := dzprv.Bytes()[32:]
		if !bytes.Equal(d1, tc.Dzprv) {
			t.Log("dzprv mismatch")
			t.Fail()

		}
		dzpub, _, err := zkey.Derive(tc.Label, blocks.GNSContext)
		if err != nil {
			t.Log("Failed dzpub: " + err.Error())
			t.Fail()
		}
		fmt.Printf("   dzpub = %s\n", hex.EncodeToString(dzpub.KeyData))
		if !bytes.Equal(dzpub.KeyData, tc.Dzpub) {
			t.Log("dzpub mismatch")
			t.Fail()
			continue
		}

		// double-check and verify derivation
		if !dzpub.Equal(dzprv.Public()) {
			t.Log("bad derived key")
			t.Fail()
			continue
		}

		// compute storage key 'q'
		q := crypto.Hash(dzpub.KeyData).Data
		fmt.Printf("   Q = %s\n", hex.EncodeToString(q))
		if !bytes.Equal(q, tc.Q) {
			fmt.Printf("    != %s\n", hex.EncodeToString(tc.Q))
			fmt.Printf("   pd = %s\n", hex.EncodeToString(dzpub.KeyData))
			t.Log("Failed: storage key mismatch")
			t.Fail()
		}

		// assemble record set and extract RDATA
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

		// encrypt RDATA into BDATA
		var ts uint64
		rdInt(tc.Enc.Expire, &ts)
		expires := util.AbsoluteTime{
			Val: ts,
		}
		skey, nLen := zkey.BlockKey(tc.Label, expires)
		if !bytes.Equal(skey[:32], tc.Enc.Key) {
			fmt.Printf("key = %s\n", hex.EncodeToString(skey[:32]))
			fmt.Printf("KEY = %s\n", hex.EncodeToString(tc.Enc.Key))
			t.Log("KEY mismatch")
			t.Fail()
			continue
		}
		if !bytes.Equal(skey[32:32+nLen], tc.Enc.Nonce) {
			fmt.Printf("nonce = %s\n", hex.EncodeToString(skey[32:32+nLen]))
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

			rdata, err := zkey.Decrypt(tc.Bdata, tc.Label, expires)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Println("RDATA = " + hex.EncodeToString(rdata))
			if bytes.Equal(rdata, tc.Rdata) {
				fmt.Println("Oops...")
			}
			continue
		}

		// assemble RRBLOCK (from GNSBlock)
		blk := blocks.NewGNSBlock().(*blocks.GNSBlock)
		blk.Prepare(enums.BLOCK_TYPE_GNS_NAMERECORD, expires)
		blk.SetData(bdata)

		// sign the block
		blk.Sign(dzprv)

		// check resulting RRBLOCK
		rrblock := blk.RRBLOCK()
		if !bytes.Equal(rrblock, tc.RRblock) {
			fmt.Printf("rrblock = %s\n", hex.EncodeToString(rrblock))
			fmt.Printf("RRBLOCK = %s\n", hex.EncodeToString(tc.RRblock))
			t.Log("RRblock mismatch")

			// PKEY/ECDSA signatures are currently not identical with
			// GNUnet produced signatures, so ignore any failures.
			if ztype != enums.GNS_TYPE_PKEY {
				t.Fail()
			}

			// check signatures
			if ok, err := blk.Verify(); !ok || err != nil {
				t.Fatal("FAILED: sig")
			}
			sd := blk.DerivedKeySig.Signature
			r := math.NewIntFromBytes(sd[:32])
			s := math.NewIntFromBytes(sd[32:])
			fmt.Printf("*** r = %s\n", hex.EncodeToString(r.Bytes()))
			fmt.Printf("*** s = %s\n", hex.EncodeToString(s.Bytes()))

			BLK := blocks.NewGNSBlock().(*blocks.GNSBlock)
			BLK.Prepare(enums.BLOCK_TYPE_GNS_NAMERECORD, expires)
			BLK.SetData(bdata)
			BLK.DerivedKeySig, err = crypto.NewZoneSignature(tc.RRblock[4:104])
			SD := BLK.DerivedKeySig.Signature
			R := math.NewIntFromBytes(SD[:32])
			S := math.NewIntFromBytes(SD[32:])
			fmt.Printf("*** R = %s\n", hex.EncodeToString(R.Bytes()))
			fmt.Printf("*** S = %s\n", hex.EncodeToString(S.Bytes()))

			if ok, err := BLK.Verify(); !ok || err != nil {
				t.Fatal("FAILED: SIG")
			}

			continue
		}
		fmt.Println("   ----- passed -----")
	}
}

func TestSigGcrypt(t *testing.T) {
	tc := tests[0]

	// Zonekey type
	var ztype enums.GNSType
	rdInt(tc.Zid, &ztype)
	fmt.Printf("   ztype = %08x (%d)\n", uint32(ztype), ztype)

	// generate private zone key
	zprv, err := crypto.NewZonePrivate(ztype, tc.Zprv)
	if err != nil {
		t.Fatal("Failed: " + err.Error())
	}
	fmt.Printf("   zprv = %s\n", hex.EncodeToString(zprv.Bytes()))

	// generate signature
	tsig, _ := zprv.Sign([]byte("sample"))

	// test result
	R := []byte{
		0x03, 0xfb, 0xaf, 0xa1, 0x40, 0xd0, 0x11, 0x12, 0x45, 0xa1, 0xa7, 0x38, 0x45, 0x77, 0x81, 0x66,
		0x4c, 0x73, 0x7f, 0x97, 0x4d, 0x53, 0x6a, 0x17, 0xf7, 0xc4, 0x9a, 0x19, 0xa4, 0x01, 0xaf, 0xd7,
	}
	S := []byte{
		0x0c, 0x42, 0xe7, 0xde, 0xbe, 0xa9, 0xeb, 0x5c, 0x9f, 0x4a, 0x30, 0xb8, 0x23, 0x22, 0xa9, 0xb2,
		0xdf, 0x37, 0x0a, 0x7d, 0xe6, 0xea, 0xa7, 0x17, 0x1c, 0x90, 0xba, 0xa1, 0x0e, 0x6e, 0x15, 0x29,
	}
	buf := tsig.Bytes()
	t.Log("r = " + hex.EncodeToString(buf[:32]))
	t.Log("s = " + hex.EncodeToString(buf[32:]))
	if !bytes.Equal(buf[:32], R) {
		t.Fatal("Failed: R mismatch")
	}
	if !bytes.Equal(buf[32:], S) {
		t.Fatal("Failed: S mismatch")
	}
}

func rdInt(data []byte, v any) {
	_ = binary.Read(bytes.NewReader(data), binary.BigEndian, v)
}

func dumpTime(s []byte) {
	var ts uint64
	rdInt(s, &ts)
	t := util.AbsoluteTime{
		Val: ts,
	}
	fmt.Printf("  // %s", t.String())
}

func dumpSize(s []byte) {
	var n uint16
	rdInt(s, &n)
	fmt.Printf("  // %d bytes", n)
}

func dumpFlags(s []byte) {
	var f enums.GNSFlag
	rdInt(s, &f)
	fmt.Printf("  // %s", strings.Join(f.List(), "|"))
}

func dumpType(s []byte) {
	var t enums.GNSType
	rdInt(s, &t)
	fmt.Printf("  // %s", t.String())
}

func dumpHex(prefix string, data []byte) {
	dumpBlk := func(b []byte) {
		for i := 0; i < len(b); i++ {
			if i > 0 {
				fmt.Printf(" ")
			}
			fmt.Printf("%02x", b[i])
		}
	}
	p2 := "                      "[:len(prefix)]
	fmt.Printf("%s", prefix)
	for len(data) > 0 {
		p := data
		if len(data) > 16 {
			p = data[:16]
		}
		dumpBlk(p)
		data = data[len(p):]
		if len(data) > 0 {
			fmt.Printf("\n%s", p2)
		}
	}
}

func dumpTxt(prefix string, txt string) {
	fmt.Printf("%s", prefix)
	for _, r := range txt {
		fmt.Printf("%c", r)
		i := len([]byte(string(r)))
		fmt.Printf("           "[:3*i-1])
	}
}
