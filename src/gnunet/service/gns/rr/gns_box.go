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

package rr

import (
	"encoding/hex"
	"strconv"
	"strings"

	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// GNS box record that embeds either a TLSA or SRV record
//----------------------------------------------------------------------

// BOX is an encapsulated RR for special names
type BOX struct {
	Proto uint16        `order:"big"` // Protcol identifier
	Svc   uint16        `order:"big"` // Service identifier
	Type  enums.GNSType `order:"big"` // Type of embedded RR
	RR    []byte        `size:"*"`    // embedded RR
}

// NewBOX creates a new box instance from a BOX resource record data.
func NewBOX(buf []byte) *BOX {
	b := new(BOX)
	if err := data.Unmarshal(b, buf); err != nil {
		logger.Printf(logger.ERROR, "[gns] Can't unmarshal BOX")
		return nil
	}
	return b
}

// Matches verifies that the remaining labels comply with the values
// in the BOX record.
func (b *BOX) Matches(labels []string) bool {
	// resolve protocol and service names
	proto, protoName := GetProtocol(labels[0])
	svc, _ := GetService(labels[1], protoName)
	// no match on invalid resolution
	if proto == 0 || svc == 0 {
		return false
	}
	// check for matching values in box
	return proto == b.Proto && svc == b.Svc
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (b *BOX) Coexist([]*enums.GNSSpec, string) (bool, enums.GNSFlag) {
	return true, 0
}

// ToMap adds the RR attributes to a stringed map
func (b *BOX) ToMap(params map[string]string, prefix string) {
	// shared attributes
	params[prefix+"proto"] = strconv.Itoa(int(b.Proto))
	params[prefix+"svc"] = strconv.Itoa(int(b.Svc))
	params[prefix+"type"] = strconv.Itoa(int(b.Type))
	// attributes of embedded record
	if rr, err := b.EmbeddedRR(); err != nil && rr != nil {
		rr.ToMap(params, prefix)
	}
}

// EmbeddedRR returns the embedded RR as an instance
func (b *BOX) EmbeddedRR() (rr RR, err error) {
	switch b.Type {
	case enums.GNS_TYPE_DNS_TLSA:
		rr = new(TLSA)
	case enums.GNS_TYPE_DNS_SRV:
		rr = new(SRV)
	}
	err = data.Unmarshal(rr, b.RR)
	return
}

//----------------------------------------------------------------------
// embedded resource records
//----------------------------------------------------------------------

var (
	// TLSAUsage for defined usage values
	TLSAUsage = map[uint8]string{
		0:   "CA certificate",
		1:   "Service certificate constraint",
		2:   "Trust anchor assertion",
		3:   "Domain-issued certificate",
		255: "Private use",
	}
	// TLSASelector for defined selector values
	TLSASelector = map[uint8]string{
		0:   "Full certificate",
		1:   "SubjectPublicKeyInfo",
		255: "Private use",
	}
	// TLSAMatch for defined match values
	TLSAMatch = map[uint8]string{
		0:   "No hash",
		1:   "SHA-256",
		2:   "SHA-512",
		255: "Private use",
	}
)

// TLSA is a DNSSEC TLS asscoication
type TLSA struct {
	Usage    uint8
	Selector uint8
	Match    uint8
	Cert     []byte `size:"*"`
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *TLSA) Coexist([]*enums.GNSSpec, string) (bool, enums.GNSFlag) {
	return true, 0
}

// ToMap adds the RR attributes to a stringed map
func (rr *TLSA) ToMap(params map[string]string, prefix string) {
	params[prefix+"tlsa_usage"] = strconv.Itoa(int(rr.Usage))
	params[prefix+"tlsa_selector"] = strconv.Itoa(int(rr.Selector))
	params[prefix+"tlsa_match"] = strconv.Itoa(int(rr.Match))
	params[prefix+"tlsa_cert"] = hex.EncodeToString(rr.Cert)
}

//----------------------------------------------------------------------

// SRV for service definitions
type SRV struct {
	Host string
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *SRV) Coexist([]*enums.GNSSpec, string) (bool, enums.GNSFlag) {
	return true, 0
}

// ToMap adds the RR attributes to a stringed map
func (rr *SRV) ToMap(params map[string]string, prefix string) {
	params[prefix+"srv_server"] = rr.Host
}

//----------------------------------------------------------------------
// BOX protocols
//----------------------------------------------------------------------

// list of handled protocols in BOX records
var protocols = map[string]uint16{
	"icmp":      1,
	"igmp":      2,
	"tcp":       6,
	"udp":       17,
	"ipv6-icmp": 58,
}

// GetProtocolName returns the name of a protocol for given nu,ber
func GetProtocolName(proto uint16) string {
	// check for valid number (reverse protocol lookup)
	for label, id := range protocols {
		if id == proto {
			// return found entry
			return label
		}
	}
	return util.CastToString(proto)
}

// GetProtocols returns a list of supported protocols for use
// by caller (e.g. UI handling)
func GetProtocols() (protos map[uint16]string) {
	protos = make(map[uint16]string)
	for name, id := range protocols {
		protos[id] = name
	}
	return
}

// GetProtocol returns the protocol number and name for a given name. The
// name can be  an integer value (e.g. "_6" for "tcp") or a mnemonic name
// (e.g. like "_tcp").
func GetProtocol(name string) (uint16, string) {
	// check for required prefix
	if name[0] != '_' {
		return 0, ""
	}
	name = strings.ToLower(name[1:])

	// if label is an integer value it is the protocol number
	if val, err := strconv.Atoi(name); err == nil {
		proto := uint16(val)
		label := GetProtocolName(proto)
		if len(label) == 0 {
			proto = 0
		}
		return proto, label
	}
	// try to resolve via protocol map
	if id, ok := protocols[name]; ok {
		return id, name
	}
	// resolution failed
	return 0, ""
}

//----------------------------------------------------------------------
// BOX services
//----------------------------------------------------------------------

// list of services (per protocol) handled in BOX records
var services = map[string]map[string]uint16{
	"udp": {
		"bootpc":    68,
		"bootps":    67,
		"domain":    53,
		"gnunet":    2086,
		"https":     443,
		"isakmp":    500,
		"kerberos4": 750,
		"kerberos":  88,
		"ldap":      389,
		"ldaps":     636,
		"ntp":       123,
		"openvpn":   1194,
		"radius":    1812,
		"rtsp":      554,
		"sip":       5060,
		"sip-tls":   5061,
		"snmp":      161,
		"syslog":    514,
		"tftp":      69,
		"who":       513,
	},
	"tcp": {
		"domain":    53,
		"finger":    79,
		"ftp":       21,
		"ftp-data":  20,
		"ftps":      990,
		"ftps-data": 989,
		"git":       9418,
		"gnunet":    2086,
		"gopher":    70,
		"http":      80,
		"https":     443,
		"imap2":     143,
		"imaps":     993,
		"kerberos4": 750,
		"kerberos":  88,
		"kermit":    1649,
		"ldap":      389,
		"ldaps":     636,
		"login":     513,
		"mysql":     3306,
		"openvpn":   1194,
		"pop3":      110,
		"pop3s":     995,
		"printer":   515,
		"radius":    1812,
		"redis":     6379,
		"rsync":     873,
		"rtsp":      554,
		"shell":     514,
		"sip":       5060,
		"sip-tls":   5061,
		"smtp":      25,
		"snmp":      161,
		"ssh":       22,
		"telnet":    23,
		"telnets":   992,
		"uucp":      540,
		"webmin":    10000,
		"x11":       6000,
	},
}

// GetServiceName returns the service spec on given port
func GetServiceName(svc, proto uint16) string {
	for n, id := range services[GetProtocolName(proto)] {
		if id == svc {
			return n
		}
	}
	return util.CastToString(svc)
}

// GetServices returns a list of supported services for use
// by caller (e.g. UI handling)
func GetServices() (svcs map[uint16]string) {
	svcs = make(map[uint16]string)
	for n, id := range services["tcp"] {
		svcs[id] = n + " (tcp"
	}
	for n, id := range services["udp"] {
		nn, ok := svcs[id]
		if ok {
			svcs[id] = nn + "/udp"
		} else {
			svcs[id] = n + " (udp"
		}
	}
	for id, n := range svcs {
		svcs[id] = n + ")"
	}
	return
}

// GetService returns the port number and the name of a service (with given
// protocol).  The name can be an integer value (e.g. "_443" for "https") or
// a mnemonic name (e.g. like "_https").
func GetService(name, proto string) (uint16, string) {
	// check for required prefix
	if name[0] != '_' {
		return 0, ""
	}
	name = strings.ToLower(name[1:])

	// get list of services for given protocol
	svcs, ok := services[proto]
	if !ok {
		// no services available for this protocol
		return 0, ""
	}

	// if label is an integer value it is the port number
	if val, err := strconv.Atoi(name); err == nil {
		svc := uint16(val)
		// check for valid number (reverse service lookup)
		for label, id := range svcs {
			if id == svc {
				// return found entry
				return svc, label
			}
		}
		// number out of range
		return 0, ""
	}
	// try to resolve via services map
	if id, ok := svcs[name]; ok {
		return id, name
	}
	// resolution failed
	return 0, ""
}
