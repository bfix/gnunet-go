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

package transport

import (
	"fmt"
	"gnunet/core"
	"gnunet/util"

	"github.com/bfix/gospel/concurrent"
)

// Transport is the genric interface for the transport layer
type Transport interface {

	// TryConnect is a function which allows the local peer to attempt the
	// establishment of a connection to another peer N using an address A.
	// When the connection attempt is successful, information on the new
	// peer is offered through the PEER_CONNECTED signal.
	TryConnect(peer core.PeerID, addr util.Address)

	// Hold is a function which tells the underlay to keep a hold on to a
	// connection to a peer P. Underlays are usually limited in the number
	// of active connections. With this function the DHT can indicate to the
	// underlay which connections should preferably be preserved.
	Hold(peer core.PeerID)

	// Drop is a function which tells the underlay to drop the connection to a
	// peer P. This function is only there for symmetry and used during the
	// peer's shutdown to release all of the remaining HOLDs. As R5N always
	// prefers the longest-lived connections, it would never drop an active
	// connection that it has called HOLD() on before. Nevertheless, underlay
	// implementations should not rely on this always being true. A call to
	// DROP() also does not imply that the underlay must close the connection:
	// it merely removes the preference to preserve the connection that was
	// established by HOLD().
	Drop(peer core.PeerID)

	// Send is a function that allows the local peer to send a protocol
	// message M to a peer P.
	Send(peer core.PeerID, msg []byte)

	// L2NSE is ESTIMATE_NETWORK_SIZE(), a procedure that provides estimates
	// on the base-2 logarithm of the network size L2NSE, that is the base-2
	// logarithm number of peers in the network, for use by the routing
	// algorithm.
	L2NSE() float64

	// Signal returns a channel for transport signals (send by the transport
	// to communicate connect and disconnect events and others)
	Signal() <-chan interface{}
}

//======================================================================
// Implementation of a simple transport mechanism (testing-only).
//======================================================================

// TestTransport is a simple UDP-based transport layer
type TestTransport struct {
	hdlr    chan Channel
	sig     <-chan interface{}
	srvc    ChannelServer
	running bool
}

func NewTestTransport() *TestTransport {
	return &TestTransport{
		hdlr:    make(chan Channel),
		sig:     make(<-chan interface{}),
		srvc:    nil,
		running: false,
	}
}

func (t *TestTransport) handle(ch Channel, sig *concurrent.Signaller) {
	buf := make([]byte, 4096)
	for {
		n, err := ch.Read(buf, sig)
		if err != nil {
			break
		}
		_, err = ch.Write(buf[:n], sig)
		if err != nil {
			break
		}
	}
	ch.Close()
}

func (s *TestTransport) Start(spec string) (err error) {
	// check if we are already running
	if s.running {
		return fmt.Errorf("Server already running")
	}

	// start channel server
	if s.srvc, err = NewChannelServer(spec, s.hdlr); err != nil {
		return
	}
	s.running = true

	// handle clients
	sig := concurrent.NewSignaller()
	go func() {
		for s.running {
			in := <-s.hdlr
			if in == nil {
				break
			}
			switch x := in.(type) {
			case Channel:
				go s.handle(x, sig)
			}
		}
		s.srvc.Close()
		s.running = false
	}()
	return nil
}

func (s *TestTransport) Stop() {
	s.running = false
}

func (t *TestTransport) TryConnect(peer core.PeerID, addr util.Address) {

}

func (t *TestTransport) Hold(peer core.PeerID) {

}

func (t *TestTransport) Drop(peer core.PeerID) {}

func (t *TestTransport) Send(peer core.PeerID, msg []byte) {}

func (t *TestTransport) L2NSE() float64 {
	return 0
}

func (t *TestTransport) Signal() <-chan interface{} {
	return nil
}
