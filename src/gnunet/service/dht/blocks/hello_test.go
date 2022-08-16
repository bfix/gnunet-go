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

package blocks

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"gnunet/util"
	"strings"
	"testing"
	"time"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
)

var (
	block *HelloBlock
	sk    *ed25519.PrivateKey
)

func setup(t *testing.T) {
	t.Helper()

	// check for initialized values
	if block != nil {
		return
	}
	// generate keys
	var pk *ed25519.PublicKey
	pk, sk = ed25519.NewKeypair()
	peer := util.NewPeerID(pk.Bytes())

	// set addresses
	addrs := []string{
		"ip+udp://172.17.0.6:2086",
		"ip+udp://245.23.42.67:2086",
	}
	addrList := make([]*util.Address, 0)
	for _, addr := range addrs {
		frag := strings.Split(addr, "://")
		e := util.NewAddress(frag[0], frag[1])
		if e == nil {
			t.Fatal("invalid address: " + addr)
		}
		addrList = append(addrList, e)
	}

	// create new HELLO block
	block = InitHelloBlock(peer, addrList, time.Hour)

	// sign block.
	sig, err := sk.EdSign(block.SignedData())
	if err != nil {
		t.Fatal(err)
	}
	block.Signature = util.NewPeerSignature(sig.Bytes())
}

func TestHelloVerify(t *testing.T) {
	setup(t)

	// verify signature
	ok, err := block.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("HELLO verify failed")
	}
}

func TestHelloURL(t *testing.T) {
	setup(t)

	// create HELLO URL
	url := block.URL()
	t.Log(url)

	// read back
	tblk, err := ParseHelloBlockFromURL(url, true)
	if err != nil {
		t.Fatal(err)
	}
	// verify identical blocks
	if !bytes.Equal(tblk.Bytes(), block.Bytes()) {
		t.Log(hex.EncodeToString(tblk.Bytes()))
		t.Log(hex.EncodeToString(block.Bytes()))
		t.Fatal("URL readback failed")
	}
}

func TestHelloBytes(t *testing.T) {
	setup(t)

	buf := block.Bytes()
	tblk, err := ParseHelloBlockFromBytes(buf)
	if err != nil {
		t.Fatal(err)
	}
	// verify identical blocks
	if !bytes.Equal(tblk.Bytes(), block.Bytes()) {
		t.Log(hex.EncodeToString(tblk.Bytes()))
		t.Log(hex.EncodeToString(block.Bytes()))
		t.Fatal("Bytes readback failed")
	}
}

func TestHelloDebug(t *testing.T) {
	blkData := "QKObXJUbnnghRh9McDDjHaB9IIL6MhhEiQHc8VfO3QMABeZZJJhsA" +
		"GlwK3VkcDovLzEyNy4wLjAuMToxMDAwMQBpcCt1ZHA6Ly8xNzIuMT" +
		"cuMC40OjEwMDAxAGlwK3VkcDovL1s6OmZmZmY6MTcyLjE3LjAuNF06MTAwMDEA"
	buf, err := base64.RawStdEncoding.DecodeString(blkData)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := ParseHelloBlockFromBytes(buf)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := hb.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		// trace problem
		t.Log("Block: " + hex.EncodeToString(buf))
		t.Log("PeerID: " + hb.PeerID.String())
		t.Log("  ->  " + hex.EncodeToString(hb.PeerID.Bytes()))
		t.Logf("Expire: %d", hb.Expire_.Val)
		t.Logf("  -> " + hb.Expire_.String())
		var exp util.AbsoluteTime
		if err = data.Unmarshal(&exp, buf[32:40]); err != nil {
			t.Fatal(err)
		}
		t.Logf("  -> " + exp.String())
		t.Log("AddrBin: " + hex.EncodeToString(hb.AddrBin))
		sd := hb.SignedData()
		t.Log("SignedData: " + hex.EncodeToString(sd))
		t.Log("Addresses:")
		for _, addr := range hb.Addresses() {
			t.Logf("* " + addr.URI())
		}
		t.Log("Signature: " + hex.EncodeToString(hb.Signature.Bytes()))
		t.Fatal("debug HELLO verify failed")
	}
}
