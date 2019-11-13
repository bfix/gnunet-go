package transport

import (
	"gnunet/core"
	"gnunet/message"
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
func (c *Connection) Send(msg message.Message) error {
	return c.ch.Send(msg)
}

// Receive a message on the connection
func (c *Connection) Receive() (message.Message, error) {
	return c.ch.Receive()
}
