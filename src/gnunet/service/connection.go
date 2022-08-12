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

package service

import (
	"context"
	"errors"
	"fmt"
	"gnunet/message"
	"gnunet/util"
	"net"
	"os"
	"strconv"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

// Error codes
var (
	ErrConnectionNotOpened   = errors.New("channel not opened")
	ErrConnectionInterrupted = errors.New("channel interrupted")
)

//======================================================================

// Connection is a channel for GNUnet message exchange (send/receive)
// based on Unix domain sockets. It is used locally by services and
// clients in the standard GNUnet environment.
type Connection struct {
	id   int      // connection identifier
	path string   // file name of Unix socket
	conn net.Conn // associated connection
	buf  []byte   // read/write buffer
}

// NewConnection creates a new connection to a socket with given path.
// This is used by clients to connect to a service.
func NewConnection(ctx context.Context, path string) (s *Connection, err error) {
	var d net.Dialer
	s = new(Connection)
	s.id = util.NextID()
	s.path = path
	s.buf = make([]byte, 65536)
	s.conn, err = d.DialContext(ctx, "unix", path)
	return
}

// Close a socket connection
func (s *Connection) Close() error {
	if s.conn != nil {
		rc := s.conn.Close()
		s.conn = nil
		return rc
	}
	return ErrConnectionNotOpened
}

// Send a GNUnet message over a socket.
func (s *Connection) Send(ctx context.Context, msg message.Message) error {
	// convert message to binary data
	data, err := data.Marshal(msg)
	if err != nil {
		return err
	}
	// check message header size and packet size
	mh, err := message.GetMsgHeader(data)
	if err != nil {
		return err
	}
	if len(data) != int(mh.MsgSize) {
		return errors.New("send: message size mismatch")
	}

	// send packet
	n, err := s.write(ctx, data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("incomplete send")
	}
	return nil
}

// Receive GNUnet messages from socket.
func (s *Connection) Receive(ctx context.Context) (message.Message, error) {
	// get bytes from socket
	get := func(pos, count int) error {
		n, err := s.read(ctx, s.buf[pos:pos+count])
		if err != nil {
			return err
		}
		if n != count {
			return errors.New("not enough bytes on network")
		}
		return nil
	}
	// read header first
	if err := get(0, 4); err != nil {
		return nil, err
	}
	mh, err := message.GetMsgHeader(s.buf[:4])
	if err != nil {
		return nil, err
	}
	// get rest of message
	if err = get(4, int(mh.MsgSize)-4); err != nil {
		return nil, err
	}
	var msg message.Message
	if msg, err = message.NewEmptyMessage(mh.MsgType); err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, fmt.Errorf("message{%d} is nil", mh.MsgType)
	}
	if err = data.Unmarshal(msg, s.buf[:mh.MsgSize]); err != nil {
		return nil, err
	}
	return msg, nil
}

// Receiver returns the receiving client (string representation)
func (s *Connection) Receiver() *util.PeerID {
	return nil
}

//----------------------------------------------------------------------
// internal methods
//----------------------------------------------------------------------

// result of read/write operations on sockets.
type result struct {
	n   int   // number of bytes read/written
	err error // error (or nil)
}

// Read bytes from a socket into buffer: Returns the number of read
// bytes and an error code. Only works on open channels ;)
func (s *Connection) read(ctx context.Context, buf []byte) (int, error) {
	// check if the channel is open
	if s.conn == nil {
		return 0, ErrConnectionNotOpened
	}
	// perform read operation
	ch := make(chan *result)
	go func() {
		n, err := s.conn.Read(buf)
		ch <- &result{n, err}
	}()
	for {
		select {
		// terminate on request
		case <-ctx.Done():
			return 0, ErrConnectionInterrupted

		// handle result of read operation
		case res := <-ch:
			return res.n, res.err
		}
	}
}

// Write buffer to socket and returns the number of bytes written and an
// optional error code.
func (s *Connection) write(ctx context.Context, buf []byte) (int, error) {
	// check if we have an open socket to write to.
	if s.conn == nil {
		return 0, ErrConnectionNotOpened
	}
	// perform write operation
	ch := make(chan *result)
	go func() {
		n, err := s.conn.Write(buf)
		ch <- &result{n, err}
	}()
	for {
		select {
		// handle terminate command
		case <-ctx.Done():
			return 0, ErrConnectionInterrupted

		// handle result of write operation
		case res := <-ch:
			return res.n, res.err
		}
	}
}

//======================================================================

// ConnectionManager to handle client connections on a socket.
type ConnectionManager struct {
	listener net.Listener // reference to listener object
	running  bool         // server running?
}

// NewConnectionManager creates a new socket connection manager. Incoming
// connections from clients are dispatched to a handler channel.
func NewConnectionManager(
	ctx context.Context, // execution context
	path string, // socket file name
	params map[string]string, // connection parameters
	hdlr chan *Connection, // handler for incoming connections
) (cs *ConnectionManager, err error) {
	// instantiate channel server
	cs = &ConnectionManager{
		listener: nil,
		running:  false,
	}
	// create listener
	var lc net.ListenConfig
	if cs.listener, err = lc.Listen(ctx, "unix", path); err != nil {
		return
	}
	// handle additional parameters
	for key, value := range params {
		switch key {
		case "perm": // set permissions on 'unix'
			if perm, err := strconv.ParseInt(value, 8, 32); err == nil {
				if err := os.Chmod(path, os.FileMode(perm)); err != nil {
					logger.Printf(
						logger.ERROR,
						"MsgChannelServer: Failed to set permissions %s on %s: %s\n",
						path, value, err.Error())
				}
			} else {
				logger.Printf(
					logger.ERROR,
					"MsgChannelServer: Invalid permissions '%s'\n",
					value)
			}
		}
	}
	// run go routine to handle channel requests from clients
	cs.running = true
	go func() {
		for cs.running {
			conn, err := cs.listener.Accept()
			if err != nil {
				break
			}
			// handle connection
			c := &Connection{
				conn: conn,
				path: path,
				buf:  make([]byte, 65536),
			}
			hdlr <- c
		}
		if cs.listener != nil {
			cs.listener.Close()
		}
	}()
	return cs, nil
}

// Close a network channel server (= stop the server)
func (s *ConnectionManager) Close() error {
	s.running = false
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}
