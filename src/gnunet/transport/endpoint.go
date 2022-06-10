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
	"strings"
	"sync"
	"time"

	"github.com/bfix/gospel/logger"
)

var (
	ErrEndpNotAvailable     = errors.New("no endpoint for address available")
	ErrEndpProtocolMismatch = errors.New("transport protocol mismatch")
	ErrEndpProtocolUnknown  = errors.New("unknown transport protocol")
	ErrEndpExists           = errors.New("endpoint exists")
	ErrEndpNoAddress        = errors.New("no address for endpoint")
	ErrEndpNoConnection     = errors.New("no connection on endpoint")
	ErrEndpMaybeSent        = errors.New("message may have been sent - cant know")
	ErrEndpWriteShort       = errors.New("write too short")
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
	netw string         // network identifier ("udp", "udp4", "udp6", ...)
	addr net.Addr       // endpoint address
	conn net.PacketConn // packet connection
	buf  []byte         // buffer for read/write operations
	mtx  sync.Mutex     // mutex for send operations
}

// Run packet endpoint: send incoming messages to the handler.
func (ep *PaketEndpoint) Run(ctx context.Context, hdlr chan *TransportMessage) (err error) {
	// create listener
	var lc net.ListenConfig
	xproto := ep.addr.Network()
	if ep.conn, err = lc.ListenPacket(ctx, EpProtocol(xproto), ep.addr.String()); err != nil {
		return
	}
	// use the actual listening address
	ep.addr = util.NewAddress(xproto, ep.conn.LocalAddr().String())

	// save more information to detect compatible send-to addresses
	ep.netw = ep.conn.LocalAddr().Network()

	// run watch dog for termination
	go func() {
		<-ctx.Done()
		ep.conn.Close()
	}()
	// run go routine to handle messages from clients
	go func() {
		for {
			// read next message
			tm, err := ep.read()
			if err != nil {
				logger.Println(logger.DBG, "[pkt_ep] read failed: "+err.Error())
				// gracefully ignore unknown message types
				if strings.HasPrefix(err.Error(), "unknown message type") {
					continue
				}
				break
			}
			// label message
			tm.Label = ep.addr.String()
			// send transport message to handler
			go func() {
				hdlr <- tm
			}()
		}
		// connection ended.
		ep.conn.Close()
	}()
	return
}

// Read a transport message from endpoint based on extended protocol
func (ep *PaketEndpoint) read() (tm *TransportMessage, err error) {
	// read next packet (assuming that it contains one complete message)
	var n int
	if n, _, err = ep.conn.ReadFrom(ep.buf); err != nil {
		return
	}
	// parse transport message based on extended protocol
	var (
		peer *util.PeerID
		msg  message.Message
	)
	switch ep.addr.Network() {
	case "ip+udp":
		// parse peer id and message in sequence
		peer = util.NewPeerID(ep.buf[:32])
		rdr := bytes.NewBuffer(util.Clone(ep.buf[32:n]))
		if msg, err = ReadMessageDirect(rdr, ep.buf); err != nil {
			return
		}
	default:
		panic(ErrEndpProtocolUnknown)
	}
	// return transport message
	return &TransportMessage{
		Peer:  peer,
		Msg:   msg,
		Resp:  nil,
		Label: "",
	}, nil
}

// Send message to address from endpoint
func (ep *PaketEndpoint) Send(ctx context.Context, addr net.Addr, msg *TransportMessage) (err error) {
	// only one sender at a time
	ep.mtx.Lock()
	defer ep.mtx.Unlock()

	// check for valid connection
	if ep.conn == nil {
		return ErrEndpNoConnection
	}

	// resolve target address
	var a *net.UDPAddr
	if a, err = net.ResolveUDPAddr(EpProtocol(addr.Network()), addr.String()); err != nil {
		return
	}

	// get message content (TransportMessage)
	var buf []byte
	if buf, err = msg.Bytes(); err != nil {
		return
	}

	// handle extended protocol:
	switch ep.addr.Network() {
	case "ip+udp":
		// no modifications required

	default:
		// unknown protocol
		return ErrEndpProtocolUnknown
	}

	// timeout after 1 second
	if err = ep.conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		logger.Println(logger.DBG, "[pkt_ep] SetWriteDeadline failed: "+err.Error())
		return
	}
	var n int
	n, err = ep.conn.WriteTo(buf, a)
	if n != len(buf) {
		err = ErrEndpWriteShort
	}
	return ErrEndpMaybeSent
}

// Address returms the
func (ep *PaketEndpoint) Address() net.Addr {
	return ep.addr
}

// CanSendTo returns true if the endpoint can sent to address
func (ep *PaketEndpoint) CanSendTo(addr net.Addr) (ok bool) {
	ok = EpProtocol(addr.Network()) == EpProtocol(ep.addr.Network())
	if ok {
		// try to convert addr to compatible type
		switch ep.netw {
		case "udp", "udp4", "udp6":
			var ua *net.UDPAddr
			var err error
			if ua, err = net.ResolveUDPAddr(ep.netw, addr.String()); err != nil {
				ok = false
			}
			logger.Printf(logger.DBG, "[pkt_ep] %s + %v -> %v (%v)", ep.netw, addr, ua, ok)
		default:
			logger.Printf(logger.DBG, "[pkt_ep] unknown network %s", ep.netw)
			ok = false
		}
	} else {
		logger.Printf(logger.DBG, "[pkt_ep] protocol mismatch %s -- %s", EpProtocol(addr.Network()), EpProtocol(ep.addr.Network()))
	}
	return
}

// ID returns the endpoint identifier
func (ep *PaketEndpoint) ID() int {
	return ep.id
}

// create a new packet endpoint for protcol and address
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
	xproto := ep.addr.Network()
	if ep.listener, err = lc.Listen(ctx, EpProtocol(xproto), ep.addr.String()); err != nil {
		return
	}
	// get actual listening address
	ep.addr = util.NewAddress(xproto, ep.listener.Addr().String())

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
					tm, err := ep.read(ctx, conn)
					if err != nil {
						break
					}
					// send transport message to handler
					go func() {
						hdlr <- tm
					}()
				}
				// connection ended.
				conn.Close()
				ep.conns.Delete(session)
			}()
		}
	}()
	return
}

// Read a transport message from endpoint based on extended protocol
func (ep *StreamEndpoint) read(ctx context.Context, conn net.Conn) (tm *TransportMessage, err error) {
	// parse transport message based on extended protocol
	var (
		peer *util.PeerID
		msg  message.Message
	)
	switch ep.addr.Network() {
	case "ip+udp":
		// parse peer id
		peer = util.NewPeerID(nil)
		if _, err = conn.Read(peer.Key); err != nil {
			return
		}
		// read next message from connection
		if msg, err = ReadMessage(ctx, conn, ep.buf); err != nil {
			break
		}
	default:
		panic(ErrEndpProtocolUnknown)
	}
	// return transport message
	return &TransportMessage{
		Peer: peer,
		Msg:  msg,
	}, nil
}

// Send message to address from endpoint
func (ep *StreamEndpoint) Send(ctx context.Context, addr net.Addr, msg *TransportMessage) error {
	return nil
}

// Address returns the actual listening endpoint address
func (ep *StreamEndpoint) Address() net.Addr {
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

// create a new endpoint based on extended protocol and address
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

//----------------------------------------------------------------------
// derive endpoint mode (packet/stream) and transport protocol from
// net.Adddr.Network() strings
//----------------------------------------------------------------------

// EpProtocol returns the transport protocol for a given network string
// that can include extended protocol information like "r5n+ip+udp"
func EpProtocol(netw string) string {
	switch netw {
	case "udp", "udp4", "udp6", "ip+udp":
		return "udp"
	case "tcp", "tcp4", "tcp6":
		return "tcp"
	case "unix":
		return "unix"
	}
	return ""
}

// epMode returns the endpoint mode (packet or stream) for a given network
func epMode(netw string) string {
	switch EpProtocol(netw) {
	case "udp":
		return "packet"
	case "tcp", "unix":
		return "stream"
	}
	return ""
}
