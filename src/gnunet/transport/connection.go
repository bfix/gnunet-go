package transport

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"gnunet/core"
	"gnunet/message"
)

type Connection interface {
}

type TCPConnection struct {
	from, to  *core.Peer
	conn      net.Conn
	buf       []byte
	bandwidth uint32
	init      bool
	state     int
	shared    []byte
}

func NewTCPConnection(conn net.Conn, from, to *core.Peer) *TCPConnection {
	return &TCPConnection{
		from:  from,
		to:    to,
		state: 1,
		conn:  conn,
		buf:   make([]byte, 65536),
	}
}

func (c *TCPConnection) SharedSecret(secret []byte) {
	c.shared = make([]byte, len(secret))
	copy(c.shared, secret)
}

func (c *TCPConnection) GetState() int {
	return c.state
}

func (c *TCPConnection) SetBandwidth(bw uint32) {
	c.bandwidth = bw
}

func (c *TCPConnection) Close() error {
	return c.conn.Close()
}

func (c *TCPConnection) Send(msg interface{}) error {

	// convert message to binary data
	data, err := message.Marshal(msg)
	if err != nil {
		return err
	}
	fmt.Printf("==> %v\n", msg)
	fmt.Printf("    [%s]\n", hex.EncodeToString(data))

	// check message header size and packet size
	mh, err := message.GetMsgHeader(data)
	if err != nil {
		return err
	}
	if len(data) != int(mh.MsgSize) {
		return errors.New("Send: message size mismatch")
	}

	// send packet
	n, err := c.conn.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("Incomplete send")
	}
	return nil
}

func (c *TCPConnection) Receive() (interface{}, uint16, error) {
	get := func(pos, count int) error {
		n, err := c.conn.Read(c.buf[pos : pos+count])
		if err != nil {
			return err
		}
		if n != count {
			return errors.New("not enough bytes on network")
		}
		return nil
	}
	if err := get(0, 4); err != nil {
		return nil, 0, err
	}
	msgSize, msgType := message.GetMessageHeader(c.buf[:4])
	if err := get(4, int(msgSize)-4); err != nil {
		return nil, 0, err
	}
	msg, err := message.NewEmptyMessage(msgType)
	if err != nil {
		return nil, 0, err
	}
	if msg == nil {
		return nil, 0, fmt.Errorf("Message{%d} is nil!\n", msgType)
	}
	if err = message.Unmarshal(msg, c.buf[:msgSize]); err != nil {
		return nil, 0, err
	}
	fmt.Printf("<== %v\n", msg)
	fmt.Printf("    [%s]\n", hex.EncodeToString(c.buf[:msgSize]))
	return msg, msgType, nil
}
