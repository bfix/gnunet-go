package transport

import (
	"gnunet/core"
	"gnunet/message"
)

////////////////////////////////////////////////////////////////////////
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

func NewConnection(ch *MsgChannel, from, to *core.Peer) *Connection {
	return &Connection{
		from:  from,
		to:    to,
		state: 1,
		ch:    ch,
	}
}

func (c *Connection) SharedSecret(secret []byte) {
	c.shared = make([]byte, len(secret))
	copy(c.shared, secret)
}

func (c *Connection) GetState() int {
	return c.state
}

func (c *Connection) SetBandwidth(bw uint32) {
	c.bandwidth = bw
}

func (c *Connection) Close() error {
	return c.ch.Close()
}

func (c *Connection) Send(msg message.Message) error {
	return c.ch.Send(msg)
}

func (c *Connection) Receive() (message.Message, uint16, error) {
	return c.ch.Receive()
}
