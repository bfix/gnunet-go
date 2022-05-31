// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2022 Bernd Fix  >Y<
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
	"net"
)

// Error codes
var (
	ErrConnectionNotOpened   = errors.New("connection not opened")
	ErrConnectionInterrupted = errors.New("connection interrupted")
)

//----------------------------------------------------------------------

// Connection is a net.Conn for GNUnet message exchange (send/receive)
type Connection struct {
	conn net.Conn // associated connection
	buf  []byte   // read/write buffer
}

// NewConnection creates a new connection from an existing net.Conn
// This is usually used by clients to connect to a service.
func NewConnection(ctx context.Context, conn net.Conn) *Connection {
	return &Connection{
		conn: conn,
		buf:  make([]byte, 65536),
	}
}

// Close connection
func (s *Connection) Close() error {
	if s.conn != nil {
		rc := s.conn.Close()
		s.conn = nil
		return rc
	}
	return ErrConnectionNotOpened
}

// Send a GNUnet message over connection
func (s *Connection) Send(ctx context.Context, msg message.Message) error {
	return WriteMessage(ctx, s.conn, msg)
}

// Receive GNUnet messages from socket.
func (s *Connection) Receive(ctx context.Context) (message.Message, error) {
	return ReadMessage(ctx, s.conn, s.buf)
}

//----------------------------------------------------------------------

// ConnectionManager handles client connections on a net.Listener
type ConnectionManager struct {
	listener net.Listener // reference to listener object
}

// NewConnectionManager creates a new net.Listener connection manager.
// Incoming connections from clients are dispatched to a handler channel.
func NewConnectionManager(ctx context.Context, listener net.Listener, hdlr chan *Connection) (cs *ConnectionManager, err error) {
	// instantiate connection manager
	cs = &ConnectionManager{
		listener: listener,
	}
	// run watch dog for termination
	go func() {
		<-ctx.Done()
		cs.listener.Close()
	}()
	// run go routine to handle channel requests from clients
	go func() {
		for {
			conn, err := cs.listener.Accept()
			if err != nil {
				return
			}
			// handle connection
			c := &Connection{
				conn: conn,
				buf:  make([]byte, 65536),
			}
			hdlr <- c
		}
	}()
	return cs, nil
}

// Close a connection manager (= stop the server)
func (s *ConnectionManager) Close() (err error) {
	if s.listener != nil {
		err = s.listener.Close()
		s.listener = nil
	}
	return
}

//----------------------------------------------------------------------

// PacketConn is a wrapper around net.PacketConn to provide ReadCloser
// and WriteCloser interfaces.
type PacketConn struct {
	conn net.PacketConn
	peer net.Addr
}

// NewPacketConn wrapes a net.PacketConn
func NewPacketConn(conn net.PacketConn) *PacketConn {
	return &PacketConn{
		conn: conn,
	}
}

// Read bytes from packet connection
func (c *PacketConn) Read(buf []byte) (int, error) {
	n, addr, err := c.conn.ReadFrom(buf)
	c.peer = addr
	return n, err
}

func (c *PacketConn) Write(buf []byte) (int, error) {
	return c.conn.WriteTo(buf, c.peer)
}

func (c *PacketConn) Close() error {
	return c.conn.Close()
}
