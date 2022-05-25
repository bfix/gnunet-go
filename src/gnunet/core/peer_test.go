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

package core

import (
	"gnunet/message"
	"gnunet/util"
	"testing"
	"time"
)

// test data
var (
	SEED = []byte{
		0x5a, 0xf7, 0x02, 0x0e, 0xe1, 0x91, 0x60, 0x32,
		0x88, 0x32, 0x35, 0x2b, 0xbc, 0x6a, 0x68, 0xa8,
		0xd7, 0x1a, 0x7c, 0xbe, 0x1b, 0x92, 0x99, 0x69,
		0xa7, 0xc6, 0x6d, 0x41, 0x5a, 0x0d, 0x8f, 0x65,
	}
	ADDRS = []string{
		"r5n+ip+udp://1.2.3.4:6789",
		"gnunet+tcp://12.3.4.5/",
	}
	TTL = 6 * time.Hour
)

func TestPeerHello(t *testing.T) {

	// generate new local node
	node, err := NewPeer(SEED, true)
	if err != nil {
		t.Fatal(err)
	}
	// add addresses
	for _, a := range ADDRS {
		addr, err := util.ParseAddress(a)
		if err != nil {
			t.Fatal(err)
		}
		node.AddAddress(addr)
	}

	// get HELLO data for the node
	h, err := node.HelloData(TTL)

	// convert to URL and back
	u := h.URL()
	t.Log(u)
	h2, err := message.ParseHelloURL(u)
	if err != nil {
		t.Fatal(err)
	}
	u2 := h2.URL()
	t.Log(u2)

	// check if HELLO data is the same
	if !h.Equals(h2) {
		t.Fatal("HELLO data mismatch")
	}
	// verify signature
	ok, err := h.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("failed to verify signature")
	}
}
