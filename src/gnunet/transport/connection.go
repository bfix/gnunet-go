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
	"gnunet/core"
	"gnunet/message"

	"github.com/bfix/gospel/concurrent"
)

// Connection for communicating peers
type Connection struct {
	from, to  *core.Peer
	ch        *MsgChannel
	buf       []byte
	bandwidth uint32
	init      bool
	state     int
	shared    []byte
}

// NewConnection instanciates a new connection between peers communicating
// over a message channel (Connections are authenticated and secured).
func NewConnection(ch *MsgChannel, from, to *core.Peer) *Connection {
	return &Connection{
		from:  from,
		to:    to,
		state: 1,
		ch:    ch,
	}
}

// SharedSecret computes the shared secret the two endpoints of a connection.
func (c *Connection) SharedSecret(secret []byte) {
	c.shared = make([]byte, len(secret))
	copy(c.shared, secret)
}

// GetState returns the current state of the connection.
func (c *Connection) GetState() int {
	return c.state
}

// SetBandwidth to control transfer rates on the connection
func (c *Connection) SetBandwidth(bw uint32) {
	c.bandwidth = bw
}

// Close connection between two peers.
func (c *Connection) Close() error {
	return c.ch.Close()
}

// Send a message on the connection
func (c *Connection) Send(msg message.Message, sig *concurrent.Signaller) error {
	return c.ch.Send(msg, sig)
}

// Receive a message on the connection
func (c *Connection) Receive(sig *concurrent.Signaller) (message.Message, error) {
	return c.ch.Receive(sig)
}
