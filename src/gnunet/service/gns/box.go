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

package gns

import (
	"encoding/hex"
	"strconv"
	"strings"

	"gnunet/enums"
	"gnunet/message"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

// Box is an encapsulated RR for special names
type Box struct {
	Proto uint16        `order:"big"` // Protcol identifier
	Svc   uint16        `order:"big"` // Service identifier
	Type  enums.GNSType `order:"big"` // Type of embedded RR
	RR    []byte        `size:"*"`    // embedded RR

	// transient attributes (not serialized)
	key string                  // map key for box instance
	rec *message.ResourceRecord // originating RR
}

// NewBox creates a new box instance from a BOX resource record.
func NewBox(rec *message.ResourceRecord) *Box {
	b := new(Box)
	if err := data.Unmarshal(b, rec.Data); err != nil {
		logger.Printf(logger.ERROR, "[gns] Can't unmarshal BOX")
		return nil
	}
	b.key = hex.EncodeToString(rec.Data[:8])
	b.rec = rec
	return b
}

// Matches verifies that the remaining labels comply with the values
// in the BOX record.
func (b *Box) Matches(labels []string) bool {
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

//----------------------------------------------------------------------
// helper functions

// list of handled protocols in BOX records
var protocols = map[string]int{
	"icmp":      1,
	"igmp":      2,
	"tcp":       6,
	"udp":       17,
	"ipv6-icmp": 58,
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
		// check for valid number (reverse protocol lookup)
		for label, id := range protocols {
			if id == val {
				// return found entry
				return uint16(val), label
			}
		}
		// number out of range
		return 0, ""
	}
	// try to resolve via protocol map
	if id, ok := protocols[name]; ok {
		return uint16(id), name
	}
	// resolution failed
	return 0, ""
}

// list of services (per protocol) handled in BOX records
var services = map[string]map[string]int{
	"udp": {
		"domain": 53,
	},
	"tcp": {
		"ftp":    21,
		"ftps":   990,
		"gopher": 70,
		"http":   80,
		"https":  443,
		"imap2":  143,
		"imap3":  220,
		"imaps":  993,
		"pop3":   110,
		"pop3s":  995,
		"smtp":   25,
		"ssh":    22,
		"telnet": 23,
	},
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
		// check for valid number (reverse service lookup)
		for label, id := range svcs {
			if id == val {
				// return found entry
				return uint16(val), label
			}
		}
		// number out of range
		return 0, ""
	}
	// try to resolve via services map
	if id, ok := svcs[name]; ok {
		return uint16(id), name
	}
	// resolution failed
	return 0, ""
}
