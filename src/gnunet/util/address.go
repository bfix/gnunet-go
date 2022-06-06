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

package util

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

// Address specifies how a peer is reachable on the network.
type Address struct {
	Netw    string       ``            // network protocol
	Options uint32       `order:"big"` // address options
	Expires AbsoluteTime ``            // expiration date for address
	Address []byte       `size:"*"`    // address data (protocol-dependent)
}

// NewAddress returns a new Address for the given transport and specs
func NewAddress(transport string, addr []byte) *Address {
	return &Address{
		Netw:    transport,
		Options: 0,
		Address: Clone(addr),
		Expires: AbsoluteTimeNever(),
	}
}

func NewAddressWrap(addr net.Addr) *Address {
	return &Address{
		Netw:    addr.Network(),
		Options: 0,
		Address: []byte(addr.String()),
		Expires: AbsoluteTimeNever(),
	}
}

// ParseAddress translates a GNUnet address string like
// "r5n+ip+udp://1.2.3.4:6789" or "gnunet+tcp://12.3.4.5/".
// It can also handle standard strings like "udp:127.0.0.1:6735".
func ParseAddress(s string) (addr *Address, err error) {
	p := strings.SplitN(s, ":", 2)
	if len(p) != 2 {
		err = fmt.Errorf("invalid address format: '%s'", s)
		return
	}
	addr = NewAddress(p[0], []byte(strings.Trim(p[1], "/")))
	return
}

// Equals return true if two addresses match.
func (a *Address) Equals(b *Address) bool {
	return a.Netw == b.Netw &&
		a.Options == b.Options &&
		bytes.Equal(a.Address, b.Address)
}

// StringAll returns a human-readable representation of an address.
func (a *Address) StringAll() string {
	return a.Netw + "://" + string(a.Address)
}

// implement net.Addr interface methods:

// String returns a human-readable representation of an address.
func (a *Address) String() string {
	return string(a.Address)
}

// Network returns the protocol specifier.
func (a *Address) Network() string {
	return a.Netw
}

//----------------------------------------------------------------------

// URI returns a string representaion of an address.
func (a *Address) URI() string {
	return URI(a.Netw, a.Address)
}
func URI(network string, addr []byte) string {
	return network + "://" + string(addr)
}

//----------------------------------------------------------------------

// IPAddress (can be IPv4 or IPv6 or a DNS name)
type IPAddress struct {
	Host []byte `size:"*-2"`
	Port uint16 `order:"big"`
}

// NewIPAddress creates a new instance for a given host and port.
func NewIPAddress(host []byte, port uint16) *IPAddress {
	ip := &IPAddress{
		Host: make([]byte, len(host)),
		Port: port,
	}
	copy(ip.Host, host)
	return ip
}

//----------------------------------------------------------------------

// PeerAddrList is a list of addresses per peer ID.
type PeerAddrList struct {
	list *Map[string, []*Address]
}

// NewPeerAddrList returns a new and empty address list.
func NewPeerAddrList() *PeerAddrList {
	return &PeerAddrList{
		list: NewMap[string, []*Address](),
	}
}

// Add address for peer. The returned mode is 0=not added, 1=new peer,
// 2=new address
func (a *PeerAddrList) Add(id string, addr *Address) (mode int) {
	// check for expired address.
	mode = 0
	if !addr.Expires.Expired() {
		// run add operation
		a.list.Process(func() error {
			list, ok := a.list.Get(id)
			if !ok {
				list = make([]*Address, 0)
				mode = 1
			} else {
				for _, a := range list {
					if a.Equals(addr) {
						return nil
					}
				}
				mode = 2
			}
			list = append(list, addr)
			a.list.Put(id, list)
			return nil
		}, false)
	}
	return
}

// Get address for peer
func (a *PeerAddrList) Get(id string, transport string) *Address {
	list, ok := a.list.Get(id)
	if ok {
		for _, addr := range list {
			// check for expired address.
			if addr.Expires.Expired() {
				// skip expired
				continue
			}
			// check for matching protocol
			if len(transport) > 0 && transport != addr.Netw {
				// skip other transports
				continue
			}
			return addr
		}
	}
	return nil
}

// Delete a list entry by key.
func (a *PeerAddrList) Delete(id string) {
	a.list.Delete(id)
}
