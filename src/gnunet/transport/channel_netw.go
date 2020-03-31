// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
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
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/bfix/gospel/concurrent"
	"github.com/bfix/gospel/logger"
)

// ChannelResult for read/write operations on channels.
type ChannelResult struct {
	count int   // number of bytes read/written
	err   error // error (or nil)
}

// NewChannelResult instanciates a new object with given attributes.
func NewChannelResult(n int, err error) *ChannelResult {
	return &ChannelResult{
		count: n,
		err:   err,
	}
}

// Values() returns the attributes of a result instance (for passing up the
// call stack).
func (cr *ChannelResult) Values() (int, error) {
	return cr.count, cr.err
}

////////////////////////////////////////////////////////////////////////
// Generic network-based Channel

// NetworkChannel
type NetworkChannel struct {
	network string   // network protocol identifier ("tcp", "unix", ...)
	conn    net.Conn // associated connection
}

// NewNetworkChannel creates a new channel for a given network protocol.
// The channel is in pending state and need to be opened before use.
func NewNetworkChannel(netw string) Channel {
	return &NetworkChannel{
		network: netw,
		conn:    nil,
	}
}

// Open a network channel based on specification:
// The specification is a string separated into parts by the '+' delimiter
// (e.g. "unix+/tmp/gnunet-service-gns-go.sock+perm=0770"). The network
// identifier (first part) must match the network specification of the
// underlaying NetworkChannel instance.
func (c *NetworkChannel) Open(spec string) (err error) {
	parts := strings.Split(spec, "+")
	// check for correct protocol
	if parts[0] != c.network {
		return ErrChannelNotImplemented
	}
	// open connection
	c.conn, err = net.Dial(c.network, parts[1])
	return
}

// Close a network channel
func (c *NetworkChannel) Close() error {
	if c.conn != nil {
		rc := c.conn.Close()
		c.conn = nil
		return rc
	}
	return ErrChannelNotOpened
}

// IsOpen returns true if the channel is opened
func (c *NetworkChannel) IsOpen() bool {
	return c.conn != nil
}

// Read bytes from a network channel into buffer: Returns the number of read
// bytes and an error code. Only works on open channels ;)
// The read can be aborted by sending 'true' on the cmd interface; the
// channel is closed after such interruption.
func (c *NetworkChannel) Read(buf []byte, sig *concurrent.Signaller) (int, error) {
	// check if the channel is open
	if c.conn == nil {
		return 0, ErrChannelNotOpened
	}
	// perform operation in go-routine
	result := make(chan *ChannelResult)
	go func() {
		result <- NewChannelResult(c.conn.Read(buf))
	}()

	listener := sig.Listen()
	defer sig.Drop(listener)
	for {
		select {
		// handle terminate command
		case x := <-listener:
			switch val := x.(type) {
			case bool:
				if val {
					c.conn.Close()
					c.conn = nil
					return 0, ErrChannelInterrupted
				}
			}
		// handle result of read operation
		case res := <-result:
			return res.Values()
		}
	}
}

// Write buffer to a network channel: Returns the number of written bytes and
// an error code. The write operation can be aborted by sending 'true' on the
// command channel; the network channel is closed after such interrupt.
func (c *NetworkChannel) Write(buf []byte, sig *concurrent.Signaller) (int, error) {
	// check if we have an open channel to write to.
	if c.conn == nil {
		return 0, ErrChannelNotOpened
	}
	// perform operation in go-routine
	result := make(chan *ChannelResult)
	go func() {
		result <- NewChannelResult(c.conn.Write(buf))
	}()

	listener := sig.Listen()
	defer sig.Drop(listener)
	for {
		select {
		// handle terminate command
		case x := <-listener:
			switch val := x.(type) {
			case bool:
				if val {
					c.conn.Close()
					return 0, ErrChannelInterrupted
				}
			}
		// handle result of read operation
		case res := <-result:
			return res.Values()
		}
	}
}

////////////////////////////////////////////////////////////////////////
// Generic network-based ChannelServer

// NetworkChannelServer
type NetworkChannelServer struct {
	network  string       // network protocol to listen on
	listener net.Listener // reference to listener object
}

// NewNetworkChannelServer
func NewNetworkChannelServer(netw string) ChannelServer {
	return &NetworkChannelServer{
		network:  netw,
		listener: nil,
	}
}

// Open a network channel server (= start running it) based on the given
// specification. For every client connection to the server, the associated
// network channel for the connection is send via the hdlr channel.
func (s *NetworkChannelServer) Open(spec string, hdlr chan<- Channel) (err error) {
	parts := strings.Split(spec, "+")
	// check for correct protocol
	if parts[0] != s.network {
		return ErrChannelNotImplemented
	}
	// create listener
	if s.listener, err = net.Listen(s.network, parts[1]); err != nil {
		return
	}
	// handle additional parameters ('key[=value]')
	for _, param := range parts[2:] {
		frag := strings.Split(param, "=")
		switch frag[0] {
		case "perm": // set permissions on 'unix'
			if s.network == "unix" {
				if perm, err := strconv.ParseInt(frag[1], 8, 32); err == nil {
					if err := os.Chmod(parts[1], os.FileMode(perm)); err != nil {
						logger.Printf(
							logger.ERROR,
							"NetworkChannelServer: Failed to set permissions: %s\n",
							err.Error())

					}
				} else {
					logger.Printf(
						logger.ERROR,
						"NetworkChannelServer: Invalid permissions '%s'\n",
						frag[1])
				}
			}
		}
	}
	// run go routine to handle channel requests from clients
	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				// signal failure and terminate
				hdlr <- nil
				break
			}
			// send channel to handler
			hdlr <- &NetworkChannel{
				network: s.network,
				conn:    conn,
			}
		}
		if s.listener != nil {
			s.listener.Close()
		}
	}()

	return nil
}

// Close a network channel server (= stop the server)
func (s *NetworkChannelServer) Close() error {
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

////////////////////////////////////////////////////////////////////////
// helper functions to instantiate network channels and servers for
// common network protocols

// NewSocketChannel: Unix Domain Socket connection
func NewSocketChannel() Channel {
	return NewNetworkChannel("unix")
}

// NewTCPChannel: TCP connection
func NewTCPChannel() Channel {
	return NewNetworkChannel("tcp")
}

// NewUDPChannel: UDP connection
func NewUDPChannel() Channel {
	return NewNetworkChannel("udp")
}

// NewSocketChannelServer: Unix Domain Socket listener
func NewSocketChannelServer() ChannelServer {
	return NewNetworkChannelServer("unix")
}

// NewTCPChannelServer: TCP listener
func NewTCPChannelServer() ChannelServer {
	return NewNetworkChannelServer("tcp")
}

// NewUDPChannelServer: UDP listener
func NewUDPChannelServer() ChannelServer {
	return NewNetworkChannelServer("udp")
}
