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
	"bytes"
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
	Hdr     *message.Header ``         // message header
	Peer    *util.PeerID    ``         // remote peer
	Payload []byte          `size:"*"` // GNUnet message

	// package-local attributes (transient)
	msg  message.Message
	endp int // id of endpoint (incoming message)
	conn int // id of connection (optional, incoming message)
}

func (msg *TransportMessage) Header() *message.Header {
	return msg.Hdr
}

func (msg *TransportMessage) Message() (m message.Message, err error) {
	if m = msg.msg; m == nil {
		rdr := bytes.NewBuffer(msg.Payload)
		m, err = ReadMessageDirect(rdr, nil)
	}
	return
}

// Bytes returns the binary representation of a transport message
func (msg *TransportMessage) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := WriteMessageDirect(buf, msg)
	return buf.Bytes(), err
}

// String returns the message in human-readable form
func (msg *TransportMessage) String() string {
	return "TransportMessage{...}"
}

// NewTransportMessage creates a message suitable for transfer
func NewTransportMessage(peer *util.PeerID, payload []byte) (tm *TransportMessage) {
	if peer == nil {
		peer = util.NewPeerID(nil)
	}
	msize := 0
	if payload != nil {
		msize = len(payload)
	}
	tm = &TransportMessage{
		Hdr: &message.Header{
			MsgSize: uint16(36 + msize),
			MsgType: message.DUMMY,
		},
		Peer:    peer,
		Payload: payload,
	}
	return
}

//----------------------------------------------------------------------

// Transport enables network-oriented (like IP, UDP, TCP or UDS)
// message exchange on multiple endpoints.
type Transport struct {
	incoming  chan *TransportMessage // messages as received from the network
	endpoints map[int]Endpoint       // list of available endpoints
}

// NewTransport creates and runs a new transport layer implementation.
func NewTransport(ctx context.Context, ch chan *TransportMessage) (t *Transport) {
	// create transport instance
	return &Transport{
		incoming:  ch,
		endpoints: make(map[int]Endpoint),
	}
}

// Send a message over suitable endpoint
func (t *Transport) Send(ctx context.Context, addr net.Addr, msg *TransportMessage) (err error) {
	for _, ep := range t.endpoints {
		if ep.CanSendTo(addr) {
			err = ep.Send(ctx, addr, msg)
			break
		}
	}
	return
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

// Endpoints returns a list of listening addresses managed by transport.
func (t *Transport) Endpoints() (list []net.Addr) {
	list = make([]net.Addr, 0)
	for _, ep := range t.endpoints {
		list = append(list, ep.Address())
	}
	return
}
