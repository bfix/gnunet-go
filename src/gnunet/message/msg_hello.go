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

package message

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gnunet/util"
	"io"
	"time"

	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------

// HelloAddress represents a (generic) peer address with expiration date:
type HelloAddress struct {
	transport string            // Name of transport
	addrSize  uint16            // Size of address entry
	expires   util.AbsoluteTime // Expiry date
	address   []byte            // Address specification
}

// NewHelloAddress create a new HELLO address from the given address
func NewHelloAddress(a *util.Address) *HelloAddress {
	// use default expiration time, but adjust it if address expires earlier
	exp := util.NewAbsoluteTime(time.Now().Add(HelloAddressExpiration))
	if exp.Compare(a.Expire) > 0 {
		exp = a.Expire
	}
	// convert address
	addr := &HelloAddress{
		transport: a.Netw,
		addrSize:  uint16(len(a.Address)),
		expires:   exp,
		address:   make([]byte, len(a.Address)),
	}
	copy(addr.address, a.Address)
	return addr
}

// ParseHelloAddress from reader
func ParseHelloAddr(rdr io.Reader) (a *HelloAddress, err error) {
	// parse \0-terminated transport
	var (
		transport []byte
		buf       = make([]byte, 1)
	)
	for {
		if _, err = rdr.Read(buf); err != nil {
			return
		}
		if buf[0] == 0 {
			break
		}
		transport = append(transport, buf[0])
	}
	// parse address size
	var asize uint16
	if err = binary.Read(rdr, binary.BigEndian, &asize); err != nil {
		return
	}
	// parse expiration time
	var exp uint64
	if err = binary.Read(rdr, binary.BigEndian, &exp); err != nil {
		return
	}
	// get address data
	adata := make([]byte, asize)
	if _, err = rdr.Read(adata); err != nil {
		return
	}
	// assemble HELLO address
	a = &HelloAddress{
		transport: string(transport),
		addrSize:  asize,
		expires:   util.AbsoluteTime{Val: exp},
		address:   adata,
	}
	return
}

// Wrap a HelloAddress into a uitl.Address
func (a *HelloAddress) Wrap() (addr *util.Address) {
	addr = util.NewAddress(a.transport, string(a.address))
	addr.Expire = a.expires
	return
}

// String returns a human-readable representation of the message.
func (a *HelloAddress) String() string {
	return fmt.Sprintf("Address{%s,expire=%s}",
		util.URI(a.transport, a.address), a.expires)
}

// Bytes returns the binary representation of a HelloAddress
func (a *HelloAddress) Bytes() []byte {
	buf := new(bytes.Buffer)
	_, err := buf.Write([]byte(a.transport))
	if err == nil {
		if err = buf.WriteByte(0); err == nil {
			if err = binary.Write(buf, binary.BigEndian, a.addrSize); err == nil {
				if err = binary.Write(buf, binary.BigEndian, a.expires.Val); err != nil {
					_, err = buf.Write(a.address)
				}
			}
		}
	}
	if err != nil {
		logger.Printf(logger.ERROR, "[HelloAddress] failed: %s", err.Error())
	}
	return buf.Bytes()
}

//----------------------------------------------------------------------
// HELLO
//
// A HELLO message is used to exchange information about transports with
// other peers. This struct is always followed by the actual network
// addresses of type "HelloAddress"
//----------------------------------------------------------------------

// HelloMsg is a message send by peers to announce their presence
type HelloMsg struct {
	MsgSize     uint16       `order:"big"` // total size of message
	MsgType     uint16       `order:"big"` // HELLO (17)
	FriendsOnly uint32       `order:"big"` // Do not gossip this HELLO message
	Peer        *util.PeerID ``            // peer identifier for addresses
	AddrList    []byte       `size:"*"`    // List of end-point addresses (HelloAddress)
}

// NewHelloMsg creates a new HELLO msg for a given peer.
func NewHelloMsg(peer *util.PeerID) *HelloMsg {
	// allocate peer id if none is specified
	if peer == nil {
		peer = util.NewPeerID(nil)
	}
	// return empty HelloMessage
	return &HelloMsg{
		MsgSize:     40,              // size without 'AddrList'
		MsgType:     HELLO,           // HELLO (17)
		FriendsOnly: 0,               // not used here
		Peer:        peer,            // associated peer
		AddrList:    make([]byte, 0), // list of addresses
	}
}

// Addresses returns the list of HelloAddress
func (m *HelloMsg) Addresses() (list []*HelloAddress, err error) {
	rdr := bytes.NewReader(m.AddrList)
	var addr *HelloAddress
	for {
		// parse address from stream
		if addr, err = ParseHelloAddr(rdr); err != nil {
			// end of stream: no more addresses
			if err == io.EOF {
				err = nil
			}
			return
		}
		list = append(list, addr)
	}
}

// String returns a human-readable representation of the message.
func (m *HelloMsg) String() string {
	return fmt.Sprintf("HelloMsg{%s: addrs=%d}", m.Peer, len(m.AddrList))
}

// SetAddresses adds addresses to the HELLO message.
func (m *HelloMsg) SetAddresses(list []*HelloAddress) {
	wrt := new(bytes.Buffer)
	for _, addr := range list {
		n, _ := wrt.Write(addr.Bytes())
		m.MsgSize += uint16(n)
	}
	m.AddrList = wrt.Bytes()
}

// Header returns the message header in a separate instance.
func (m *HelloMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}
