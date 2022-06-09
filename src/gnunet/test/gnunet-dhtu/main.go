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

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"gnunet/config"
	"gnunet/core"
	"gnunet/util"
	"log"
	"time"
)

//----------------------------------------------------------------------
// Test Go node with DHTU GNUnet nodes
//----------------------------------------------------------------------

func main() {
	// handle command-line arguments
	var (
		remoteId   string
		remoteAddr string
		localAddr  string
		localPort  int
	)
	flag.StringVar(&remoteId, "i", "", "peer id of remote node")
	flag.StringVar(&remoteAddr, "a", "", "address of remote node")
	flag.StringVar(&localAddr, "l", "127.0.0.1", "listening address of local node")
	flag.IntVar(&localPort, "p", 2086, "port of local node")
	flag.Parse()

	// convert arguments
	var (
		rId   *util.PeerID
		rAddr *util.Address
		buf   []byte
		err   error
	)
	if rAddr, err = util.ParseAddress(remoteAddr); err != nil {
		log.Fatal(err)
	}
	if len(remoteId) > 0 {
		if buf, err = util.DecodeStringToBinary(remoteId, 32); err != nil {
			log.Fatal(err)
		}
		rId = util.NewPeerID(buf)
	}

	// configuration data
	var (
		peerCfg = &config.NodeConfig{
			Name:        "p1",
			PrivateSeed: "iYK1wSi5XtCP774eNFk1LYXqKlOPEpwKBw+2/bMkE24=",
			Endpoints: []*config.EndpointConfig{
				{
					ID:      "p1",
					Network: "ip+udp",
					Address: localAddr,
					Port:    localPort,
					TTL:     86400,
				},
			},
		}
	)

	// setup execution context
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		time.Sleep(time.Second)
	}()

	// create and run node
	node, err := NewTestNode(ctx, peerCfg)
	if err != nil {
		log.Fatal(err)
	}
	defer node.Shutdown()

	// show our HELLO URL
	as := fmt.Sprintf("%s://%s:%d",
		peerCfg.Endpoints[0].Network,
		peerCfg.Endpoints[0].Address,
		peerCfg.Endpoints[0].Port,
	)
	listen, err := util.ParseAddress(as)
	if err != nil {
		log.Fatal(err)
	}
	aList := []*util.Address{listen}
	log.Println("HELLO: " + node.HelloURL(aList))

	// learn bootstrap address (triggers HELLO)
	node.Learn(ctx, rId, rAddr)

	// run forever
	var ch chan struct{}
	<-ch
}

//----------------------------------------------------------------------
// create and run a node with given spec
//----------------------------------------------------------------------

type TestNode struct {
	id   int
	peer *core.Peer
	core *core.Core
	addr *util.Address
}

func (n *TestNode) Shutdown() {
	n.core.Shutdown()
}
func (n *TestNode) HelloURL(a []*util.Address) string {
	hd, err := n.peer.HelloData(time.Hour, a)
	if err != nil {
		return ""
	}
	return hd.URL()
}

func (n *TestNode) Learn(ctx context.Context, peer *util.PeerID, addr *util.Address) {
	label := "@"
	if peer != nil {
		label = peer.String()
	}
	log.Printf("[%d] Learning %s for %s", n.id, addr.StringAll(), label)
	if err := n.core.Learn(ctx, peer, addr); err != nil {
		log.Println("Learn: " + err.Error())
	}
}

func NewTestNode(ctx context.Context, cfg *config.NodeConfig) (node *TestNode, err error) {

	// create test node
	node = new(TestNode)
	node.id = util.NextID()

	// create core service
	if node.core, err = core.NewCore(ctx, cfg); err != nil {
		return
	}
	node.peer = node.core.Peer()
	log.Printf("[%d] Node %s starting", node.id, node.peer.GetID())
	log.Printf("[%d]   --> %s", node.id, hex.EncodeToString(node.peer.GetID().Key))

	list, err := node.core.Addresses()
	if err != nil {
		log.Fatal(err)
	}
	for _, addr := range list {
		s := addr.Network() + "://" + addr.String()
		if node.addr, err = util.ParseAddress(s); err != nil {
			continue
		}
		log.Printf("[%d] Listening on %s", node.id, s)
	}

	// register as event listener
	incoming := make(chan *core.Event)
	node.core.Register(cfg.Name, core.NewListener(incoming, nil))

	// heart beat
	tick := time.NewTicker(5 * time.Minute)

	// run event handler
	go func() {
		for {
			select {
			// show incoming event
			case ev := <-incoming:
				switch ev.ID {
				case core.EV_CONNECT:
					log.Printf("[%d] <<< Peer %s connected", node.id, ev.Peer)
				case core.EV_DISCONNECT:
					log.Printf("[%d] <<< Peer %s diconnected", node.id, ev.Peer)
				case core.EV_MESSAGE:
					log.Printf("[%d] <<< Msg from %s of type %d", node.id, ev.Peer, ev.Msg.Header().MsgType)
					log.Printf("[%d] <<<    --> %s", node.id, ev.Msg.String())
				}

			// handle termination signal
			case <-ctx.Done():
				log.Printf("[%d] Shutting down node", node.id)
				return

			// handle heart beat
			case now := <-tick.C:
				log.Printf("[%d] Heart beat at %s", node.id, now.String())
			}
		}
	}()
	return
}
