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
	"flag"
	"fmt"
	"gnunet/config"
	"gnunet/core"
	"gnunet/message"
	"gnunet/service"
	"gnunet/service/dht"
	"gnunet/transport"
	"gnunet/util"
	"log"
	"net/rpc"
	"time"

	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// Test Go node with DHTU GNUnet nodes
//
// N.B.: THIS TEST ONLY COVERS THE BASIC MESSAGE EXCHANGE LEVEL; NO
// MESSAGE PROCESSING EXCEPT FOR HELLO MESSAGES WILL TAKE PLACE.
//----------------------------------------------------------------------

func main() {
	defer func() {
		logger.Println(logger.INFO, "[main] Shutting down...")
		logger.Flush()
	}()

	// handle command-line arguments
	var remoteAddr string
	var cfgFile string
	flag.StringVar(&cfgFile, "c", "gnunet-config.json", "configuration file")
	flag.StringVar(&remoteAddr, "a", "", "address of remote node")
	flag.Parse()

	// read configuration file and set missing arguments.
	logger.Println(logger.INFO, "[main] Parsing configuration...")
	if err := config.ParseConfig(cfgFile); err != nil {
		logger.Printf(logger.ERROR, "[main] Invalid configuration file: %s\n", err.Error())
		return
	}

	// convert arguments
	logger.Println(logger.INFO, "[main] Converting remote peer address...")
	var rAddr *util.Address
	var err error
	if rAddr, err = util.ParseAddress(remoteAddr); err != nil {
		logger.Println(logger.ERROR, err.Error())
		return
	}

	// setup execution context
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		time.Sleep(time.Second)
	}()

	// create and run node
	logger.Println(logger.INFO, "[main] Starting DHTU node...")
	node, err := NewTestNode(ctx)
	if err != nil {
		logger.Println(logger.ERROR, err.Error())
		return
	}
	defer node.Shutdown()

	// show our HELLO URL
	ep := config.Cfg.Local.Endpoints[0]
	as := fmt.Sprintf("%s://%s:%d", ep.Network, ep.Address, ep.Port)
	listen, err := util.ParseAddress(as)
	if err != nil {
		logger.Println(logger.ERROR, err.Error())
		return
	}
	aList := []*util.Address{listen}
	logger.Println(logger.INFO, "[main] --> "+node.HelloURL(aList))

	// send HELLO to bootstrap address
	if err = node.SendHello(ctx, rAddr); err != nil && err != transport.ErrEndpMaybeSent {
		logger.Println(logger.ERROR, "[main] failed to send HELLO: "+err.Error())
		return
	}

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
	hd, err := n.peer.HelloData(message.HelloAddressExpiration, a)
	if err != nil {
		return ""
	}
	return hd.URL()
}

func (n *TestNode) SendHello(ctx context.Context, addr *util.Address) error {
	return n.core.SendHello(ctx, addr)
}

func NewTestNode(ctx context.Context) (node *TestNode, err error) {

	// create test node
	node = new(TestNode)
	node.id = util.NextID()

	// create core service
	if node.core, err = core.NewCore(ctx, config.Cfg.Local); err != nil {
		return
	}
	node.peer = node.core.Peer()
	logger.Printf(logger.INFO, "[node] Node %s starting", node.peer.GetID())

	// start a new DHT service
	dht, err := dht.NewService(ctx, node.core)
	if err != nil {
		log.Fatal(err)
	}

	// start JSON-RPC server on request
	var rpc *rpc.Server
	if rpc, err = service.StartRPC(ctx, config.Cfg.RPC.Endpoint); err != nil {
		logger.Printf(logger.ERROR, "[node] RPC failed to start: %s", err.Error())
		return
	}
	dht.InitRPC(rpc)

	// start listening on the network
	list, err := node.core.Addresses()
	if err != nil {
		log.Fatal(err)
	}
	for _, addr := range list {
		s := addr.Network() + "://" + addr.String()
		if node.addr, err = util.ParseAddress(s); err != nil {
			continue
		}
		logger.Printf(logger.INFO, "[node] Listening on %s", s)
	}

	// register as event listener
	incoming := make(chan *core.Event)
	node.core.Register(config.Cfg.Local.Name, core.NewListener(incoming, nil))

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
					logger.Printf(logger.INFO, "[node] <<< Peer %s connected", ev.Peer)
				case core.EV_DISCONNECT:
					logger.Printf(logger.INFO, "[node] <<< Peer %s diconnected", ev.Peer)
				case core.EV_MESSAGE:
					logger.Printf(logger.INFO, "[node] <<< Msg from %s of type %d", ev.Peer, ev.Msg.Header().MsgType)
					logger.Printf(logger.INFO, "[node] <<<    --> %s", ev.Msg.String())
				}

			// handle termination signal
			case <-ctx.Done():
				logger.Println(logger.INFO, "[node] Shutting down node")
				return

			// handle heart beat
			case now := <-tick.C:
				logger.Printf(logger.INFO, "[node] Heart beat at %s", now.String())
			}
		}
	}()
	return
}
