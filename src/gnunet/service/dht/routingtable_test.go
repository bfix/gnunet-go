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
	"context"
	"gnunet/config"
	"gnunet/core"
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
	cfg = &config.NodeConfig{
		PrivateSeed: "YGoe6XFH3XdvFRl+agx9gIzPTvxA229WFdkazEMdcOs=",
		Endpoints: []string{
			"r5n+ip+udp://127.0.0.1:6666",
		},
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

	// establish context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// create routing table and start command handler
	local, err := core.NewLocalPeer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rt := NewRoutingTable(NewPeerAddress(local.GetID()))
	ch := rt.Run(ctx)

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
		ch <- &RTCommand{
			Cmd:  RtcConnect,
			Data: task.addr,
		}
		task.online = true
		task.last = e
		t.Logf("[%6d] %s %s\n", e, task.addr, msg)
	}
	disconnected := func(task *Entry, e int64, msg string) {
		ch <- &RTCommand{
			Cmd:  RtcDisconnect,
			Data: task.addr,
		}
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
	bf := NewPeerBloomFilter()
	n := rt.SelectClosestPeer(k, bf)
	t.Logf("Closest: %s -> %s\n", k, n)

	n = rt.SelectRandomPeer(bf)
	t.Logf("Random: %s\n", n)
}
