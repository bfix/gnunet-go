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

package util

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

// Address specifies how a peer is reachable on the network.
type Address struct {
	Netw    string       // network protocol
	Options uint32       // address options
	Expire  AbsoluteTime // expiration date for address
	Address []byte       // address data (protocol-dependent)
}

// NewAddress returns a new Address for the given transport and specs
func NewAddress(transport string, addr string) *Address {
	return &Address{
		Netw:    transport,
		Options: 0,
		Address: Clone([]byte(addr)),
		Expire:  AbsoluteTimeNever(),
	}
}

// NewAddressWrap returns new address from net.Addr with no options
// or expiry date.
func NewAddressWrap(addr net.Addr) *Address {
	return &Address{
		Netw:    addr.Network(),
		Options: 0,
		Address: []byte(addr.String()),
		Expire:  AbsoluteTimeNever(),
	}
}

// ParseAddress translates a GNUnet address string like
// "ip+udp://1.2.3.4:6789" or "gnunet+tcp://12.3.4.5/".
// It can also handle standard strings like "udp:127.0.0.1:6735".
func ParseAddress(s string) (addr *Address, err error) {
	p := strings.SplitN(s, ":", 2)
	if len(p) != 2 {
		err = fmt.Errorf("invalid address format: '%s'", s)
		return
	}
	addr = NewAddress(p[0], strings.Trim(p[1], "/"))
	return
}

// Equal return true if two addresses match.
func (a *Address) Equal(b *Address) bool {
	return a.Netw == b.Netw &&
		a.Options == b.Options &&
		bytes.Equal(a.Address, b.Address)
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

// URI returns a string representation of an address.
func (a *Address) URI() string {
	return URI(a.Netw, a.Address)
}
func URI(network string, addr []byte) string {
	return network + "://" + string(addr)
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
func (a *PeerAddrList) Add(peer *PeerID, addr *Address) (mode int) {
	// check for expired address.
	mode = 0
	if !addr.Expire.Expired() {
		// run add operation
		_ = a.list.Process(func(pid int) error {
			id := peer.String()
			list, ok := a.list.Get(id, pid)
			if !ok {
				list = make([]*Address, 0)
				mode = 1
			} else {
				for _, a := range list {
					if a.Equal(addr) {
						return nil
					}
				}
				mode = 2
			}
			list = append(list, addr)
			a.list.Put(id, list, pid)
			return nil
		}, false)
	}
	return
}

// Get address for peer
func (a *PeerAddrList) Get(peer *PeerID, transport string) (res []*Address) {
	id := peer.String()
	list, ok := a.list.Get(id, 0)
	if ok {
		for _, addr := range list {
			// check for expired address.
			if addr.Expire.Expired() {
				// skip expired
				continue
			}
			// check for matching protocol
			if len(transport) > 0 && transport != addr.Netw {
				// skip other transports
				continue
			}
			res = append(res, addr)
		}
	}
	return
}

// Delete a list entry by key.
func (a *PeerAddrList) Delete(peer *PeerID) {
	a.list.Delete(peer.String(), 0)
}

// Contains checks if a peer is contained in the list. Does not check
// for expired entries.
func (a *PeerAddrList) Contains(peer *PeerID) (ok bool) {
	_, ok = a.list.Get(peer.String(), 0)
	return
}
