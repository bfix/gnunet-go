package util

import (
	"fmt"
)

type IPAddress struct {
	Host []byte `size:"*-2"`
	Port uint16 `order:"big"`
}

func NewIPAddress(host []byte, port uint16) *IPAddress {
	ip := &IPAddress{
		Host: make([]byte, len(host)),
		Port: port,
	}
	copy(ip.Host, host)
	return ip
}

type Address struct {
	Transport string
	Options   uint32 `order:"big"`
	Address   []byte `size:"*"`
}

func NewAddress(transport string, addr []byte) *Address {
	a := &Address{
		Transport: transport,
		Options:   0,
		Address:   make([]byte, len(addr)),
	}
	copy(a.Address, addr)
	return a
}

func (a *Address) String() string {
	return fmt.Sprintf("Address{%s}", AddressString(a.Transport, a.Address))
}
