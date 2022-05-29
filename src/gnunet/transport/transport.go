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
	"gnunet/message"
	"gnunet/util"
	"sync"

	"github.com/bfix/gospel/concurrent"
)

// Event identifier
const (
	EV_CONNECT = iota
	EV_DISCONNECT
	EV_MESSAGE
)

// Signal send by the transport mechanism to communicate events
type Signal struct {
	Ev   int             // event identifier
	Peer *util.PeerID    // remote peer
	Msg  message.Message // message received
	Ch   *MsgChannel     // channel for responses
}

// Transport is the genric interface for the transport layer
type Transport interface {

	// TryConnect is a function which allows the local peer to attempt the
	// establishment of a connection to another peer N using an address A.
	// When the connection attempt is successful, information on the new
	// peer is offered through the PEER_CONNECTED signal.
	TryConnect(peer *util.PeerID)

	// Hold is a function which tells the underlay to keep a hold on to a
	// connection to a peer P. Underlays are usually limited in the number
	// of active connections. With this function the DHT can indicate to the
	// underlay which connections should preferably be preserved.
	Hold(peer *util.PeerID)

	// Drop is a function which tells the underlay to drop the connection to a
	// peer P. This function is only there for symmetry and used during the
	// peer's shutdown to release all of the remaining HOLDs. As R5N always
	// prefers the longest-lived connections, it would never drop an active
	// connection that it has called HOLD() on before. Nevertheless, underlay
	// implementations should not rely on this always being true. A call to
	// DROP() also does not imply that the underlay must close the connection:
	// it merely removes the preference to preserve the connection that was
	// established by HOLD().
	Drop(peer *util.PeerID)

	// Send is a function that allows the local peer to send a protocol
	// message M to a peer P.
	Send(peer *util.PeerID, msg message.Message)

	// L2NSE is ESTIMATE_NETWORK_SIZE(), a procedure that provides estimates
	// on the base-2 logarithm of the network size L2NSE, that is the base-2
	// logarithm number of peers in the network, for use by the routing
	// algorithm.
	L2NSE() float64

	// Signal returns a channel for transport signals (send by the transport
	// to communicate connect and disconnect events, incoming messages and
	// other information)
	Signal() <-chan *Signal
}

//======================================================================
// Implementation of a simple transport mechanism (testing-only).
//======================================================================

// Session for peer connection
type Session struct {
	OnHold bool        // don't drop this session
	Ch     *MsgChannel // message exchange
}

// TestTransport is a simple UDP-based transport layer
type TestTransport struct {
	ctx      *concurrent.Signaller // service context
	hdlr     chan Channel          // handler for incoming traffic
	sig      chan *Signal          // signal channel
	srvc     ChannelServer         // connection manager
	running  bool                  // transport running?
	sessions map[string]*Session   // list of open sessions
	rwlock   sync.RWMutex          // lock for sessions map
	peers    *util.AddrList        // list of known peers with addresses
}

// NewTestTransport instantiates a simple UDP-based transport layer
func NewTestTransport() *TestTransport {
	return &TestTransport{
		hdlr:     make(chan Channel),
		sig:      make(chan *Signal),
		srvc:     nil,
		running:  false,
		sessions: make(map[string]*Session),
		peers:    util.NewAddrList(),
	}
}

// Start a transport service for given spec:
//     "unix+/tmp/test.sock" -- for UDS channels
//     "tcp+1.2.3.4:5"       -- for TCP channels
//     "udp+1.2.3.4:5"       -- for UDP channels
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
	s.ctx = concurrent.NewSignaller()
	go func() {
		for s.running {
			// wait for next request
			in := <-s.hdlr
			if in == nil {
				break
			}
			switch x := in.(type) {
			// new connection established
			case Channel:
				go s.handle(x)
			}
		}
		s.srvc.Close()
		s.running = false
	}()
	return nil
}

// Stop a transport service
func (s *TestTransport) Stop() {
	s.running = false
}

// TryConnect is a function which allows the local peer to attempt the
// establishment of a connection to another peer using an address.
// When the connection attempt is successful, information on the new
// peer is offered through the PEER_CONNECTED signal.
func (t *TestTransport) TryConnect(peer *util.PeerID) {}

// Hold is a function which tells the underlay to keep a hold on to a
// connection to a peer P. Underlays are usually limited in the number
// of active connections. With this function the DHT can indicate to the
// underlay which connections should preferably be preserved.
func (t *TestTransport) Hold(peer *util.PeerID) {
	// one map writer at a time
	t.rwlock.Lock()
	defer t.rwlock.Unlock()

	// if the session is known, it is put on hold.
	if sess, ok := t.sessions[peer.String()]; ok {
		sess.OnHold = true
	}
}

// Drop is a function which tells the underlay to drop the connection to a
// peer P. This function is only there for symmetry and used during the
// peer's shutdown to release all of the remaining HOLDs. As R5N always
// prefers the longest-lived connections, it would never drop an active
// connection that it has called HOLD() on before. Nevertheless, underlay
// implementations should not rely on this always being true. A call to
// DROP() also does not imply that the underlay must close the connection:
// it merely removes the preference to preserve the connection that was
// established by HOLD().
func (t *TestTransport) Drop(peer *util.PeerID) {
	// one map writer at a time
	t.rwlock.Lock()
	defer t.rwlock.Unlock()

	// if the session is known, unhold it.
	if sess, ok := t.sessions[peer.String()]; ok {
		sess.OnHold = false
	}
}

// Send is a function that allows the local peer to send a protocol
// message M to a peer P.
func (t *TestTransport) Send(peer *util.PeerID, msg message.Message) {
	// reader-only
	t.rwlock.RLock()
	defer t.rwlock.RUnlock()

	// if the session is known, send message to peer
	if sess, ok := t.sessions[peer.String()]; ok {
		sess.Ch.Send(msg, t.ctx)
	}
}

// L2NSE is ESTIMATE_NETWORK_SIZE(), a procedure that provides estimates
// on the base-2 logarithm of the network size L2NSE, that is the base-2
// logarithm number of peers in the network, for use by the routing
// algorithm.
func (t *TestTransport) L2NSE() float64 {
	return 0
}

// Signal returns a channel for transport signals (send by the transport
// layer to communicate connect and disconnect events and others)
func (t *TestTransport) Signal() <-chan *Signal {
	return t.sig
}

//----------------------------------------------------------------------
//----------------------------------------------------------------------

// handle incoming traffic
func (t *TestTransport) handle(ch Channel) {
	msgCh := NewMsgChannel(ch)
	for {
		// receive next message
		msg, err := msgCh.Receive(t.ctx)
		if err != nil {
			panic(err)
		}
		// prepare signal
		sig := &Signal{
			Ch: msgCh,
		}
		// inspect message for peer state events
		switch x := msg.(type) {
		case *message.HelloMsg:
			// start session
			sig.Ev = EV_CONNECT
			sig.Peer = x.PeerID
			id := sig.Peer.String()
			t.rwlock.Lock()
			t.sessions[id] = &Session{
				OnHold: false,
				Ch:     msgCh,
			}
			// keep peer addresses
			for _, addr := range x.Addresses {
				a := &util.Address{
					Transport: addr.Transport,
					Address:   addr.Address,
					Expires:   addr.ExpireOn,
				}
				t.peers.Add(id, a)
			}
			t.rwlock.Unlock()
			/*
				case *message.HangupMsg:
					// quit session
					t.rwlock.Lock()
					delete(t.sessions, x.PeerID.String())
					t.rwlock.Unlock()
			*/
		}
		// forward message
		t.sig <- sig
	}
}
