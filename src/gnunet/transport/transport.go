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
	"context"
	"errors"
	"gnunet/message"
	"gnunet/util"
	"net"
)

// Trnsport layer error codes
var (
	ErrTransNoEndpoint = errors.New("no matching endpoint found")
)

//======================================================================
// Network-oriented transport implementation
//======================================================================

// TransportMessage is the unit processed by the transport mechanism.
// Peer refers to the remote endpoint (sender/receiver) and
// Msg is the exchanged GNUnet message. The packet itself satisfies the
// message.Message interface.
type TransportMessage struct {
	Hdr  *message.Header
	Peer *util.PeerID    // remote peer
	Msg  message.Message // GNUnet message

	// package-local attributes (transient)
	endp int // id of endpoint (incoming message)
	conn int // id of connection (optional, incoming message)
}

// Header returns the message header.
func (msg *TransportMessage) Header() *message.Header {
	return msg.Hdr
}

// String returns the message in human-readable form
func (msg *TransportMessage) String() string {
	return "TransportMessage{...}"
}

// NewTransportMessage creates a message suitable for transfer
func NewTransportMessage(peer *util.PeerID, msg message.Message) *TransportMessage {
	return &TransportMessage{
		Hdr: &message.Header{
			MsgType: message.DUMMY, // used for tagging transport messages
			MsgSize: msg.Header().Size() + 8,
		},
		Peer: peer,
		Msg:  msg,
	}
}

//----------------------------------------------------------------------

// Transport enables network-oriented (like IP, UDP, TCP or UDS)
// message exchange on multiple endpoints.
type Transport struct {
	incoming  chan *TransportMessage // messages as received from the network
	endpoints map[int]Endpoint       // list of available endpoints
	peers     *util.PeerAddrList     // list of known peers with addresses
}

// NewTransport creates and runs a new transport layer implementation.
func NewTransport(ctx context.Context, ch chan *TransportMessage) (t *Transport) {
	// create transport instance
	return &Transport{
		incoming:  ch,
		endpoints: make(map[int]Endpoint),
		peers:     util.NewPeerAddrList(),
	}
}

//----------------------------------------------------------------------
// Endpoint handling
//----------------------------------------------------------------------

// AddEndpoint instantiates and run a new endpoint handler for the
// given address (must map to a network interface).
func (t *Transport) AddEndpoint(ctx context.Context, addr net.Addr) (a net.Addr, err error) {
	// register endpoint
	var ep Endpoint
	if ep, err = NewEndpoint(addr); err != nil {
		return
	}
	t.endpoints[ep.ID()] = ep
	ep.Run(ctx, t.incoming)
	return ep.Address(), nil
}

// TryConnect is a function which allows the local peer to attempt the
// establishment of a connection to another peer using an address.
// When the connection attempt is successful, information on the new
// peer is offered through the PEER_CONNECTED signal.
func (t *Transport) TryConnect(peer *util.PeerID, addr net.Addr) error {
	// select endpoint for address
	if ep := t.findEndpoint(peer, addr); ep == nil {
		return ErrTransNoEndpoint
	}
	return nil
}

func (t *Transport) findEndpoint(peer *util.PeerID, addr net.Addr) Endpoint {
	return nil
}

// Hold is a function which tells the underlay to keep a hold on to a
// connection to a peer P. Underlays are usually limited in the number
// of active connections. With this function the DHT can indicate to the
// underlay which connections should preferably be preserved.
func (t *Transport) Hold(peer *util.PeerID) {}

// Drop is a function which tells the underlay to drop the connection to a
// peer P. This function is only there for symmetry and used during the
// peer's shutdown to release all of the remaining HOLDs. As R5N always
// prefers the longest-lived connections, it would never drop an active
// connection that it has called HOLD() on before. Nevertheless, underlay
// implementations should not rely on this always being true. A call to
// DROP() also does not imply that the underlay must close the connection:
// it merely removes the preference to preserve the connection that was
// established by HOLD().
func (t *Transport) Drop(peer *util.PeerID) {}

// Send is a function that allows the local peer to send a protocol
// message to a remote peer. The transport will
func (t *Transport) Send(peer *util.PeerID, msg message.Message) {}

// L2NSE is ESTIMATE_NETWORK_SIZE(), a procedure that provides estimates
// on the base-2 logarithm of the network size L2NSE, that is the base-2
// logarithm number of peers in the network, for use by the routing
// algorithm.
func (t *Transport) L2NSE() float64 {
	return 0.
}

func (t *Transport) Learn(peer *util.PeerID, addr net.Addr) {}
