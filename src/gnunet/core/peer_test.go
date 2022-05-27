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
	"gnunet/config"
	"gnunet/service/dht/blocks"
	"testing"
	"time"
)

// test data
var (
	cfg = &config.NodeConfig{
		PrivateSeed: "YGoe6XFH3XdvFRl+agx9gIzPTvxA229WFdkazEMdcOs=",
		Endpoints: []string{
			"r5n+ip+udp://127.0.0.1:6666",
		},
	}
	TTL = 6 * time.Hour
)

func TestPeerHello(t *testing.T) {

	// generate new local node
	node, err := NewLocalPeer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// get HELLO data for the node
	h, err := node.HelloData(TTL)

	// convert to URL and back
	u := h.URL()
	t.Log(u)
	h2, err := blocks.ParseHelloURL(u)
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
