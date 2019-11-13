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
