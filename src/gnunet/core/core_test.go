// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2022 Bernd Fix  >Y<
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
	"context"
	"gnunet/config"
	"gnunet/util"
	"testing"
	"time"
)

var (
	peer1Cfg = &config.NodeConfig{
		PrivateSeed: "iYK1wSi5XtCP774eNFk1LYXqKlOPEpwKBw+2/bMkE24=",
		Endpoints:   []string{"udp://127.0.0.1:20861"},
	}

	peer2Cfg = &config.NodeConfig{
		PrivateSeed: "Bv9umksEO51jjWWrOGEH+4r8wl9Vi+LItpdBpTOi2PE=",
		Endpoints:   []string{"udp://127.0.0.1:20862"},
	}
)

//----------------------------------------------------------------------
// create and run a node with given spec
//----------------------------------------------------------------------

type TestNode struct {
	id   int
	t    *testing.T
	peer *Peer
	core *Core
	addr *util.Address
}

func (n *TestNode) Learn(ctx context.Context, peer *util.PeerID, addr *util.Address) {
	n.t.Logf("[%d] Learning %s for %s", n.id, addr.StringAll(), peer.String())
	n.core.Learn(ctx, peer, addr)
}

func NewTestNode(t *testing.T, ctx context.Context, cfg *config.NodeConfig) (node *TestNode, err error) {

	// create test node
	node = new(TestNode)
	node.t = t
	node.id = util.NextID()

	// create peer object
	if node.peer, err = NewLocalPeer(cfg); err != nil {
		return
	}
	t.Logf("[%d] Node %s starting", node.id, node.peer.GetID())

	// create core service
	if node.core, err = NewCore(ctx, node.peer); err != nil {
		return
	}
	for _, addr := range node.core.trans.Endpoints() {
		s := addr.Network() + ":" + addr.String()
		if node.addr, err = util.ParseAddress(s); err != nil {
			continue
		}
		t.Logf("[%d] Listening on %s", node.id, s)
	}

	// register as event listener
	incoming := make(chan *Event)
	node.core.Register("test", NewListener(incoming, nil))

	// heart beat
	tick := time.NewTicker(5 * time.Minute)

	// run event handler
	go func() {
		for {
			select {
			// show incoming event
			case ev := <-incoming:
				switch ev.ID {
				case EV_CONNECT:
					t.Logf("[%d] <<< Peer %s connected", node.id, ev.Peer)
				case EV_DISCONNECT:
					t.Logf("[%d] <<< Peer %s diconnected", node.id, ev.Peer)
				case EV_MESSAGE:
					t.Logf("[%d] <<< Msg from %s of type %d", node.id, ev.Peer, ev.Msg.Header().MsgType)
				}

			// handle termination signal
			case <-ctx.Done():
				t.Logf("[%d] Shutting down node", node.id)
				return

			// handle heart beat
			case now := <-tick.C:
				t.Logf("[%d] Heart beat at %s", node.id, now.String())
			}
		}
	}()
	return
}

//----------------------------------------------------------------------
// Two node GNUnet (smallest and simplest network)
//----------------------------------------------------------------------

// TestCoreSimple test a two node network
func TestCoreSimple(t *testing.T) {

	// setup execution context
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		time.Sleep(time.Second)
	}()

	// create and run nodes
	node1, err := NewTestNode(t, ctx, peer1Cfg)
	if err != nil {
		t.Fatal(err)
	}
	node2, err := NewTestNode(t, ctx, peer2Cfg)
	if err != nil {
		t.Fatal(err)
	}

	// learn peer addresses (triggers HELLO)
	for _, addr := range node2.core.trans.Endpoints() {
		node1.Learn(ctx, node2.peer.GetID(), util.NewAddressWrap(addr))
	}

	// wait for 5 seconds
	time.Sleep(5 * time.Second)
}
