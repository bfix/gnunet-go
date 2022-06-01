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

var (
	ErrEndpNotAvailable     = errors.New("no endpoint for address available")
	ErrEndpProtocolMismatch = errors.New("transport protocol mismatch")
)

// Endpoint represents a local endpoint that can send and receive messages.
// Implementations need to manage the relations between peer IDs and
// remote endpoints for TCP and UDP traffic.
type Endpoint interface {
	// Run the endpoint and send received messages to channel
	Run(context.Context, chan *TransportMessage) error

	// Send message on endpoint
	Send(context.Context, net.Addr, *TransportMessage) error

	// Address returns the listening address for the endpoint
	Address() net.Addr

	// CanSendTo returns true if the endpoint can sent to address
	CanSendTo(net.Addr) bool

	// Return endpoint identifier
	ID() int
}

//----------------------------------------------------------------------

// NewEndpoint returns a suitable endpoint for the address.
func NewEndpoint(addr net.Addr) (ep Endpoint, err error) {
	switch epMode(addr.Network()) {
	case "packet":
		ep, err = newPacketEndpoint(addr)
	case "stream":
		ep, err = newStreamEndpoint(addr)
	default:
		err = ErrEndpNotAvailable
	}
	return
}

//----------------------------------------------------------------------
// Packet-oriented endpoint
//----------------------------------------------------------------------

// PacketEndpoint for packet-oriented network protocols
type PaketEndpoint struct {
	id   int            // endpoint identifier
	addr net.Addr       // endpoint address
	conn net.PacketConn // packet connection
	buf  []byte         // buffer for read/write operations
}

// Run packet endpoint: send incoming messages to the handler.
func (ep *PaketEndpoint) Run(ctx context.Context, hdlr chan *TransportMessage) (err error) {
	// create listener
	var lc net.ListenConfig
	if ep.conn, err = lc.ListenPacket(ctx, ep.addr.Network(), ep.addr.String()); err != nil {
		return
	}

	// run watch dog for termination
	go func() {
		<-ctx.Done()
		ep.conn.Close()
	}()
	// run go routine to handle messages from clients
	go func() {
		for {
			// read next message from packet
			n, _, err := ep.conn.ReadFrom(ep.buf)
			if err != nil {
				break
			}
			rdr := bytes.NewBuffer(util.Clone(ep.buf[:n]))
			msg, err := ReadMessageDirect(rdr, ep.buf)
			if err != nil {
				break
			}
			// check for transport message
			if msg.Header().MsgType == message.DUMMY {
				// set transient attributes
				tm := msg.(*TransportMessage)
				tm.endp = ep.id
				tm.conn = 0
				// send to handler
				go func() {
					hdlr <- tm
				}()
			}
		}
		// connection ended.
		ep.conn.Close()
	}()
	return
}

// Send message to address from endpoint
func (ep *PaketEndpoint) Send(ctx context.Context, addr net.Addr, msg *TransportMessage) (err error) {
	var a *net.UDPAddr
	a, err = net.ResolveUDPAddr(addr.Network(), addr.String())
	var buf []byte
	if buf, err = msg.Bytes(); err != nil {
		return
	}
	_, err = ep.conn.WriteTo(buf, a)
	return
}

// Address returms the
func (ep *PaketEndpoint) Address() net.Addr {
	if ep.conn != nil {
		return ep.conn.LocalAddr()
	}
	return ep.addr
}

// CanSendTo returns true if the endpoint can sent to address
func (ep *PaketEndpoint) CanSendTo(addr net.Addr) bool {
	return epMode(addr.Network()) == "packet"
}

// ID returns the endpoint identifier
func (ep *PaketEndpoint) ID() int {
	return ep.id
}

func newPacketEndpoint(addr net.Addr) (ep *PaketEndpoint, err error) {
	// check for matching protocol
	if epMode(addr.Network()) != "packet" {
		err = ErrEndpProtocolMismatch
		return
	}
	// create endpoint
	ep = &PaketEndpoint{
		id:   util.NextID(),
		addr: addr,
		buf:  make([]byte, 65536),
	}
	return
}

//----------------------------------------------------------------------
// Stream-oriented endpoint
//----------------------------------------------------------------------

// StreamEndpoint for stream-oriented network protocols
type StreamEndpoint struct {
	id       int                      // endpoint identifier
	addr     net.Addr                 // listening address
	listener net.Listener             // listener instance
	conns    *util.Map[int, net.Conn] // active connections
	buf      []byte                   // read/write buffer
}

// Run packet endpoint: send incoming messages to the handler.
func (ep *StreamEndpoint) Run(ctx context.Context, hdlr chan *TransportMessage) (err error) {
	// create listener
	var lc net.ListenConfig
	if ep.listener, err = lc.Listen(ctx, ep.addr.Network(), ep.addr.String()); err != nil {
		return
	}
	// run watch dog for termination
	go func() {
		<-ctx.Done()
		ep.listener.Close()
	}()
	// run go routine to handle messages from clients
	go func() {
		for {
			// get next client connection
			conn, err := ep.listener.Accept()
			if err != nil {
				return
			}
			session := util.NextID()
			ep.conns.Put(session, conn)
			go func() {
				for {
					// read next message from connection
					msg, err := ReadMessage(ctx, conn, ep.buf)
					if err != nil {
						break
					}
					// check for transport message
					if msg.Header().MsgType == message.DUMMY {
						// set transient attributes
						tm := msg.(*TransportMessage)
						tm.endp = ep.id
						tm.conn = session
						// send to handler
						go func() {
							hdlr <- tm
						}()
					}
				}
				// connection ended.
				conn.Close()
				ep.conns.Delete(session)
			}()
		}
	}()
	return
}

// Send message to address from endpoint
func (ep *StreamEndpoint) Send(ctx context.Context, addr net.Addr, msg *TransportMessage) error {
	return nil
}

// Address returns the actual listening endpoint address
func (ep *StreamEndpoint) Address() net.Addr {
	if ep.listener != nil {
		return ep.listener.Addr()
	}
	return ep.addr
}

// CanSendTo returns true if the endpoint can sent to address
func (ep *StreamEndpoint) CanSendTo(addr net.Addr) bool {
	return epMode(addr.Network()) == "stream"
}

// ID returns the endpoint identifier
func (ep *StreamEndpoint) ID() int {
	return ep.id
}

func newStreamEndpoint(addr net.Addr) (ep *StreamEndpoint, err error) {
	// check for matching protocol
	if epMode(addr.Network()) != "stream" {
		err = ErrEndpProtocolMismatch
		return
	}
	// create endpoint
	ep = &StreamEndpoint{
		id:    util.NextID(),
		addr:  addr,
		conns: util.NewMap[int, net.Conn](),
		buf:   make([]byte, 65536),
	}
	return
}

// epMode returns the endpoint mode (packet or stream) for a given network
func epMode(netw string) string {
	switch netw {
	case "udp", "udp4", "udp6", "r5n+ip+udp":
		return "packet"
	case "tcp", "unix":
		return "stream"
	}
	return ""
}
