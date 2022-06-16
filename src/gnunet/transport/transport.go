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

	"github.com/bfix/gospel/network"
)

// Trnsport layer error codes
var (
	ErrTransNoEndpoint = errors.New("no matching endpoint found")
	ErrTransNoUPNP     = errors.New("no UPnP available")
)

//======================================================================
// Network-oriented transport implementation
//======================================================================

// TransportMessage is the unit processed by the transport mechanism.
// Peer refers to the remote endpoint (sender/receiver) and
// Msg is the exchanged GNUnet message. The packet itself satisfies the
// message.Message interface.
type TransportMessage struct {
	// Peer is a identifier for a remote peer
	Peer *util.PeerID

	// Msg is a generic GNnet message
	Msg message.Message

	// Non-serialized (transient) attributes:

	// Resp is an optional custom endpoint responder that can be set by
	// endpoints for messages received from the internet if they want to
	// handle responses directly (instead of core/transport/endpoint
	// resolving the return path). Set to nil if not used.
	Resp Responder

	// Label for log messages during message processing
	Label string
}

// Bytes returns the binary representation of a transport message
func (msg *TransportMessage) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	// serialize peer id
	if _, err := buf.Write(msg.Peer.Key); err != nil {
		return nil, err
	}
	// serialize message
	err := WriteMessageDirect(buf, msg.Msg)
	return buf.Bytes(), err
}

// String returns the message in human-readable form
func (msg *TransportMessage) String() string {
	return "TransportMessage{...}"
}

// NewTransportMessage creates a message suitable for transfer
func NewTransportMessage(peer *util.PeerID, msg message.Message) (tm *TransportMessage) {
	if peer == nil {
		peer = util.NewPeerID(nil)
	}
	tm = &TransportMessage{
		Peer:  peer,
		Msg:   msg,
		Resp:  nil,
		Label: "",
	}
	return
}

//----------------------------------------------------------------------

// Transport enables network-oriented (like IP, UDP, TCP or UDS)
// message exchange on multiple endpoints.
type Transport struct {
	incoming  chan *TransportMessage   // messages as received from the network
	endpoints *util.Map[int, Endpoint] // list of available endpoints
	upnp      *network.PortMapper      // UPnP mapper (optional)
}

// NewTransport creates and runs a new transport layer implementation.
func NewTransport(ctx context.Context, tag string, ch chan *TransportMessage) (t *Transport) {
	// create transport instance
	mngr, err := network.NewPortMapper(tag)
	if err != nil {
		mngr = nil
	}
	return &Transport{
		incoming:  ch,
		endpoints: util.NewMap[int, Endpoint](),
		upnp:      mngr,
	}
}

// Shutdown transport-related processes
func (t *Transport) Shutdown() {
	if t.upnp != nil {
		t.upnp.Close()
	}
}

// Send a message over suitable endpoint
func (t *Transport) Send(ctx context.Context, addr net.Addr, msg *TransportMessage) (err error) {
	// select best endpoint able to handle address
	var bestEp Endpoint
	err = t.endpoints.ProcessRange(func(_ int, ep Endpoint) error {
		if ep.CanSendTo(addr) {
			if bestEp == nil {
				bestEp = ep
			}
			// TODO: compare endpoints, select better one:
			// if ep.Better(bestEp) {
			//     bestEp = ep
			// }
		}
		return nil
	}, true)
	if err != nil {
		return
	}
	return bestEp.Send(ctx, addr, msg)
}

//----------------------------------------------------------------------
// Endpoint handling
//----------------------------------------------------------------------

// AddEndpoint instantiates and run a new endpoint handler for the
// given address (must map to a network interface).
func (t *Transport) AddEndpoint(ctx context.Context, addr *util.Address) (ep Endpoint, err error) {
	// check for valid address
	if addr == nil {
		err = ErrEndpNoAddress
		return
	}
	// check if endpoint is already available
	as := addr.Network() + "://" + addr.String()
	if err = t.endpoints.ProcessRange(func(_ int, ep Endpoint) error {
		ae := ep.Address().Network() + "://" + ep.Address().String()
		if as == ae {
			return ErrEndpExists
		}
		return nil
	}, true); err != nil {
		return
	}
	// register new endpoint
	if ep, err = NewEndpoint(addr); err != nil {
		return
	}
	// add endpoint to list and run it
	t.endpoints.Put(ep.ID(), ep)
	ep.Run(ctx, t.incoming)
	return
}

//----------------------------------------------------------------------
// UPnP handling
//----------------------------------------------------------------------

// ForwardOpen returns a local address for listening that will receive traffic
// from a port forward handled by UPnP on the router.
func (t *Transport) ForwardOpen(protocol, param string, port int) (id, local, remote string, err error) {
	// check for available UPnP
	if t.upnp == nil {
		err = ErrTransNoUPNP
		return
	}
	// no parameters currently defined, so just do the assignment.
	return t.upnp.Assign(protocol, port)
}

// ForwardClose closes a specific port forwarding
func (t *Transport) ForwardClose(id string) error {
	// check for available UPnP
	if t.upnp == nil {
		return ErrTransNoUPNP
	}
	return t.upnp.Unassign(id)
}
