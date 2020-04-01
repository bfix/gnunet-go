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
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"

	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/concurrent"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

// Error codes
var (
	ErrChannelNotImplemented = fmt.Errorf("Protocol not implemented")
	ErrChannelNotOpened      = fmt.Errorf("Channel not opened")
	ErrChannelInterrupted    = fmt.Errorf("Channel interrupted")
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
	Open(spec string) error                           // open channel (for read/write)
	Close() error                                     // close open channel
	IsOpen() bool                                     // check if channel is open
	Read([]byte, *concurrent.Signaller) (int, error)  // read from channel
	Write([]byte, *concurrent.Signaller) (int, error) // write to channel
}

// ChannelFactory instantiates specific Channel imülementations.
type ChannelFactory func() Channel

// Known channel implementations.
var channelImpl = map[string]ChannelFactory{
	"unix": NewSocketChannel,
	"tcp":  NewTCPChannel,
	"udp":  NewUDPChannel,
}

// NewChannel creates a new channel to the specified endpoint.
// Called by a client to connect to a service.
func NewChannel(spec string) (Channel, error) {
	parts := strings.Split(spec, "+")
	if fac, ok := channelImpl[parts[0]]; ok {
		inst := fac()
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
}

// ChannelServerFactory instantiates specific ChannelServer imülementations.
type ChannelServerFactory func() ChannelServer

// Known channel server implementations.
var channelServerImpl = map[string]ChannelServerFactory{
	"unix": NewSocketChannelServer,
	"tcp":  NewTCPChannelServer,
	"udp":  NewUDPChannelServer,
}

// NewChannelServer
func NewChannelServer(spec string, hdlr chan<- Channel) (cs ChannelServer, err error) {
	parts := strings.Split(spec, "+")

	if fac, ok := channelServerImpl[parts[0]]; ok {
		// check if the basedir for the spec exists...
		if err = util.EnforceDirExists(path.Dir(parts[1])); err != nil {
			return
		}
		// instantiate server implementation
		cs = fac()
		// create the domain socket and listen to it.
		err = cs.Open(spec, hdlr)
		return
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
func (c *MsgChannel) Send(msg message.Message, sig *concurrent.Signaller) error {
	// convert message to binary data
	data, err := data.Marshal(msg)
	if err != nil {
		return err
	}
	logger.Printf(logger.DBG, "==> %v\n", msg)
	logger.Printf(logger.DBG, "    [%s]\n", hex.EncodeToString(data))

	// check message header size and packet size
	mh, err := message.GetMsgHeader(data)
	if err != nil {
		return err
	}
	if len(data) != int(mh.MsgSize) {
		return errors.New("Send: message size mismatch")
	}

	// send packet
	n, err := c.ch.Write(data, sig)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("Incomplete send")
	}
	return nil
}

// Receive GNUnet messages over a plain Channel.
func (c *MsgChannel) Receive(sig *concurrent.Signaller) (message.Message, error) {
	// get bytes from channel
	get := func(pos, count int) error {
		n, err := c.ch.Read(c.buf[pos:pos+count], sig)
		if err != nil {
			return err
		}
		if n != count {
			return errors.New("not enough bytes on network")
		}
		return nil
	}

	if err := get(0, 4); err != nil {
		return nil, err
	}
	mh, err := message.GetMsgHeader(c.buf[:4])
	if err != nil {
		return nil, err
	}

	if err := get(4, int(mh.MsgSize)-4); err != nil {
		return nil, err
	}
	msg, err := message.NewEmptyMessage(mh.MsgType)
	if err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, fmt.Errorf("Message{%d} is nil!\n", mh.MsgType)
	}
	if err = data.Unmarshal(msg, c.buf[:mh.MsgSize]); err != nil {
		return nil, err
	}
	logger.Printf(logger.DBG, "<== %v\n", msg)
	logger.Printf(logger.DBG, "    [%s]\n", hex.EncodeToString(c.buf[:mh.MsgSize]))
	return msg, nil
}
