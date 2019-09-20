package util

import (
	"encoding/hex"
	"fmt"
	"net"
)

func AddressString(transport string, addr []byte) string {
	if transport == "tcp" || transport == "udp" {
		alen := len(addr)
		port := uint(addr[alen-2])*256 + uint(addr[alen-1])
		return fmt.Sprintf("%s:%s:%d", transport, net.IP(addr[:alen-2]).String(), port)
	}
	return fmt.Sprintf("%s:%s", transport, hex.EncodeToString(addr))
}

var scale = " kMGTPEO"

func Scale1024(n uint64) string {
	v := float64(n)
	var i int
	for i = 0; v > 1024; i++ {
		v /= 1024
	}
	if i == 0 {
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%.3f%c", v, scale[i])
}
