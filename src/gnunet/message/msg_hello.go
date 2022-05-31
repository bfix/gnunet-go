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
	"fmt"
	"gnunet/util"
)

//----------------------------------------------------------------------
// HELLO
//
// A HELLO message is used to exchange information about transports with
// other peers. This struct is always followed by the actual network
// addresses which have the format:
//
// 1) transport-name (0-terminated)
// 2) address-length (uint16_t, network byte order)
// 3) address expiration
// 4) address (address-length bytes)
//----------------------------------------------------------------------

// HelloAddress represents a (generic) peer address with expiration date
type HelloAddress struct {
	Transport string            // Name of transport
	AddrSize  uint16            `order:"big"` // Size of address entry
	ExpireOn  util.AbsoluteTime // Expiry date
	Address   []byte            `size:"AddrSize"` // Address specification
}

// NewHelloAddress create a new HELLO address from the given address
func NewHelloAddress(a *util.Address) *HelloAddress {
	addr := &HelloAddress{
		Transport: a.Netw,
		AddrSize:  uint16(len(a.Address)),
		ExpireOn:  a.Expires,
		Address:   make([]byte, len(a.Address)),
	}
	copy(addr.Address, a.Address)
	return addr
}

// String returns a human-readable representation of the message.
func (a *HelloAddress) String() string {
	return fmt.Sprintf("Address{%s,expire=%s}",
		util.AddressString(a.Transport, a.Address), a.ExpireOn)
}

// HelloMsg is a message send by peers to announce their presence
type HelloMsg struct {
	MsgSize    uint16          `order:"big"` // total size of message
	MsgType    uint16          `order:"big"` // HELLO (17)
	FriendOnly uint32          `order:"big"` // =1: do not gossip this HELLO
	PeerID     *util.PeerID    // EdDSA public key (long-term)
	Addresses  []*HelloAddress `size:"*"` // List of end-point addressess
}

// NewHelloMsg creates a new HELLO msg for a given peer.
func NewHelloMsg(peerid *util.PeerID) *HelloMsg {
	if peerid == nil {
		peerid = util.NewPeerID(nil)
	}
	return &HelloMsg{
		MsgSize:    40,
		MsgType:    HELLO,
		FriendOnly: 0,
		PeerID:     peerid,
		Addresses:  make([]*HelloAddress, 0),
	}
}

// String returns a human-readable representation of the message.
func (m *HelloMsg) String() string {
	return fmt.Sprintf("HelloMsg{peer=%s,friendsonly=%d,addr=%v}",
		m.PeerID, m.FriendOnly, m.Addresses)
}

// AddAddress adds a new address to the HELLO message.
func (m *HelloMsg) AddAddress(a *HelloAddress) {
	m.Addresses = append(m.Addresses, a)
	m.MsgSize += uint16(len(a.Transport)) + a.AddrSize + 11
}

// Header returns the message header in a separate instance.
func (m *HelloMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}
