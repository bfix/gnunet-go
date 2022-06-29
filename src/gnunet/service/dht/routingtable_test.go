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

package dht

import (
	"crypto/sha512"
	"encoding/hex"
	"gnunet/config"
	"gnunet/core"
	"gnunet/service/dht/blocks"
	"gnunet/util"
	"math/rand"
	"testing"
)

const (
	NUMP   = 1000  // Total number of peers
	EPOCHS = 10000 // number of epochs to run
)

type Entry struct {
	addr   *PeerAddress // address of peer
	ttl    int64        // time to live (in epochs)
	born   int64        // epoch of birth
	last   int64        // last action
	drop   int64        // drop (in epochs)
	revive int64        // revive dropped (in epochs)
	online bool         // peer connected?
}

// test data
var (
	nodeCfg = &config.NodeConfig{
		PrivateSeed: "YGoe6XFH3XdvFRl+agx9gIzPTvxA229WFdkazEMdcOs=",
		Endpoints: []*config.EndpointConfig{
			{
				Network: "r5n+ip+udp",
				Address: "127.0.0.1",
				Port:    6666,
			},
		},
	}
	rtCfg = &config.RoutingConfig{
		PeerTTL: 10800,
	}
)

// TestRT connects and disconnects random peers to test the base
// functionality of the routing table algorithms.
func TestRT(t *testing.T) {
	// start deterministic randomizer
	rand.Seed(19031962)

	// helper functions
	genRemotePeer := func() *PeerAddress {
		d := make([]byte, 32)
		if _, err := rand.Read(d); err != nil {
			panic(err)
		}
		return NewPeerAddress(util.NewPeerID(d))
	}

	// create routing table and start command handler
	local, err := core.NewLocalPeer(nodeCfg)
	if err != nil {
		t.Fatal(err)
	}
	rt := NewRoutingTable(NewPeerAddress(local.GetID()), rtCfg)

	// create a task list
	tasks := make([]*Entry, NUMP)
	for i := range tasks {
		tasks[i] = new(Entry)
		tasks[i].addr = genRemotePeer()
		tasks[i].born = rand.Int63n(EPOCHS)
		tasks[i].ttl = 1000 + rand.Int63n(7000)
		tasks[i].drop = 2000 + rand.Int63n(3000)
		tasks[i].revive = rand.Int63n(2000)
		tasks[i].online = false
	}

	// actions:
	connected := func(task *Entry, e int64, msg string) {
		rt.Add(task.addr)
		task.online = true
		task.last = e
		t.Logf("[%6d] %s %s\n", e, task.addr, msg)
	}
	disconnected := func(task *Entry, e int64, msg string) {
		rt.Remove(task.addr)
		task.online = false
		task.last = e
		t.Logf("[%6d] %s %s\n", e, task.addr, msg)
	}

	// run epochs
	var e int64
	for e = 0; e < EPOCHS; e++ {
		for _, task := range tasks {
			// birth
			if task.born == e {
				connected(task, e, "connected")
				continue
			}
			// death
			if task.born+task.ttl == e {
				disconnected(task, e, "disconnected")
				continue
			}
			if task.online {
				// drop out
				if task.last+task.drop == e {
					disconnected(task, e, "dropped out")
					continue
				}
			} else {
				// drop in
				if task.last+task.drop == e {
					connected(task, e, "dropped in")
					continue
				}
			}
		}
	}

	// execute some routing functions on remaining table
	k := genRemotePeer()
	pf := blocks.NewPeerFilter()
	n := rt.SelectClosestPeer(k, pf)
	t.Logf("Closest: %s -> %s\n", k, n)

	n = rt.SelectRandomPeer(pf)
	t.Logf("Random: %s\n", n)
}

func TestDistance(t *testing.T) {
	pid1 := "4ER9C0GV4QC25GGQMXBBGXYFEB3ZVAYMXZVSRKDVEGCDTAS34E30"
	pid2 := "V61ESQ96AFXZWDSA509HP11K5HJXXJ9ECM4NAMCQRX5YW4KN8XPG"

	p1, _ := util.DecodeStringToBinary(pid1, 32)
	p2, _ := util.DecodeStringToBinary(pid2, 32)

	h1 := sha512.Sum512(p1)
	h2 := sha512.Sum512(p2)
	t.Logf("h1=%s\n", hex.EncodeToString(h1[:]))
	t.Logf("h2=%s\n", hex.EncodeToString(h2[:]))

	pa1 := NewPeerAddress(util.NewPeerID(p1))
	pa2 := NewPeerAddress(util.NewPeerID(p2))

	dist, idx := pa1.Distance(pa2)
	t.Logf("dist=%v, idx=%d\n", dist, idx)
}
