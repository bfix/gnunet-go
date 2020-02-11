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
	"encoding/hex"
	"fmt"
	"net"
)

// Address specifies how a peer is reachable on the network.
type Address struct {
	Transport string // transport protocol
	Options   uint32 `order:"big"` // address options
	Address   []byte `size:"*"`    // address data (protocol-dependent)
}

// NewAddress returns a new Address for the given transport and specs
func NewAddress(transport string, addr []byte) *Address {
	a := &Address{
		Transport: transport,
		Options:   0,
		Address:   make([]byte, len(addr)),
	}
	copy(a.Address, addr)
	return a
}

// String returns a human-readable representation of an address.
func (a *Address) String() string {
	return fmt.Sprintf("Address{%s}", AddressString(a.Transport, a.Address))
}

//----------------------------------------------------------------------

// AddressString returns a string representaion of an address.
func AddressString(transport string, addr []byte) string {
	if transport == "tcp" || transport == "udp" {
		alen := len(addr)
		port := uint(addr[alen-2])*256 + uint(addr[alen-1])
		return fmt.Sprintf("%s:%s:%d", transport, net.IP(addr[:alen-2]).String(), port)
	}
	return fmt.Sprintf("%s:%s", transport, hex.EncodeToString(addr))
}

//----------------------------------------------------------------------

// IP address (can be IPv4 or IPv6 or a DNS name)
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
