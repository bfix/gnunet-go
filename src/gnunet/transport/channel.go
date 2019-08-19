package transport

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"gnunet/message"
)

var (
	ErrChannelNotImplemented = fmt.Errorf("Protocol not implemented")
	ErrChannelNotOpened      = fmt.Errorf("Channel not opened")
)

////////////////////////////////////////////////////////////////////////
// CHANNEL

// Channel is an abstraction for exchanging arbitrary data over various
// transport protocols and mechanisms. They are created by clients via
// 'NewChannel()' or by services run via 'NewChannelServer()'.
// A string specifies the end-point of the channel:
//     "unix+/tmp/test.sock" -- for UDS channels
//     "tcp+1.2.3.4:5"       -- for TCP channels
//     "udp+1.2.3.4:5"       -- for UDP channels
type Channel interface {
	Open(spec string) error
	Close() error
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Clone() Channel
}

// Known channel implementations.
var channelImpl = map[string]Channel{
	"unix": NewNetworkChannel("unix"),
	"tcp":  NewNetworkChannel("tcp"),
	"udp":  NewNetworkChannel("udp"),
}

// NewChannel creates a new channel to the specified endpoint.
// Called by a client to connect to a service.
func NewChannel(spec string) (Channel, error) {
	parts := strings.Split(spec, "+")
	if tpl, ok := channelImpl[parts[0]]; ok {
		inst := tpl.Clone()
		err := inst.Open(spec)
		return inst, err
	}
	return nil, ErrChannelNotImplemented
}

////////////////////////////////////////////////////////////////////////
// CHANNEL SERVER

// ChannelServer creates a listener for the specified endpoint.
// The specification string has the same format as for Channel with slightly
// different semantics (for TCP, and ICMP the address specifies is a mask
// for client addresses accepted for a channel request).
type ChannelServer interface {
	Open(spec string, hdlr chan<- Channel) error
	Close() error
	Clone() ChannelServer
}

// Known channel server implementations.
var channelServerImpl = map[string]ChannelServer{
	"unix": NewNetworkChannelServer("unix"),
	"tcp":  NewNetworkChannelServer("tcp"),
	"udp":  NewNetworkChannelServer("udp"),
}

// NewChannelServer
func NewChannelServer(spec string, hdlr chan<- Channel) (ChannelServer, error) {
	parts := strings.Split(spec, "+")
	if tpl, ok := channelServerImpl[parts[0]]; ok {
		inst := tpl.Clone()
		err := inst.Open(spec, hdlr)
		return inst, err
	}
	return nil, ErrChannelNotImplemented
}

////////////////////////////////////////////////////////////////////////
// MESSAGE CHANNEL

// MsgChannel s a wrapper around a generic channel for GNUnet message exchange.
type MsgChannel struct {
	ch  Channel
	buf []byte
}

// NewMsgChannel wraps a plain Channel for GNUnet message exchange.
func NewMsgChannel(ch Channel) *MsgChannel {
	return &MsgChannel{
		ch:  ch,
		buf: make([]byte, 65536),
	}
}

// Close a MsgChannel by closing the wrapped plain Channel.
func (c *MsgChannel) Close() error {
	return c.ch.Close()
}

// Send a GNUnet message over a channel.
func (c *MsgChannel) Send(msg message.Message) error {

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
	n, err := c.ch.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("Incomplete send")
	}
	return nil
}

// Receive GNUnet messages over a plain Channel.
func (c *MsgChannel) Receive() (message.Message, uint16, error) {
	get := func(pos, count int) error {
		n, err := c.ch.Read(c.buf[pos : pos+count])
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
