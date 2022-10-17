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

package zonemaster

import (
	"encoding/hex"
	"errors"
	"gnunet/enums"
	"gnunet/service/gns"
	"gnunet/service/store"
	"gnunet/util"
	"net"

	"github.com/bfix/gospel/data"
)

var (
	// list of managed RR types
	rrtypes = []enums.GNSType{
		enums.GNS_TYPE_PKEY,      // PKEY zone delegation
		enums.GNS_TYPE_EDKEY,     // EDKEY zone delegation
		enums.GNS_TYPE_REDIRECT,  // GNS delegation by name
		enums.GNS_TYPE_GNS2DNS,   // DNS delegation by name
		enums.GNS_TYPE_NICK,      // Nick name
		enums.GNS_TYPE_LEHO,      // Legacy hostname
		enums.GNS_TYPE_BOX,       // Boxed resource record
		enums.GNS_TYPE_DNS_A,     // IPv4 address
		enums.GNS_TYPE_DNS_AAAA,  // IPv6 address
		enums.GNS_TYPE_DNS_CNAME, // CNAME in DNS
		enums.GNS_TYPE_DNS_TXT,   // DNS TXT
		enums.GNS_TYPE_DNS_MX,    // Mailbox
	}
)

//----------------------------------------------------------------------
// RR data types
//----------------------------------------------------------------------

// RRtlsa is a TLSA record in a BOX
type RRtlsa struct {
	Usage    uint8
	Selector uint8
	Match    uint8
	Cert     []byte `size:"*"`
}

type RRmx struct {
	Prio   uint16 `order:"big"`
	Server []byte `size:"*"`
}

//======================================================================
// Convert binary resource records to ParameterSet and vice-versa.
// The map keys must match the HTML names of dialog fields.
//======================================================================

var (
	// List of key prefixes based on RR type
	dlgPrefix = map[enums.GNSType]string{
		enums.GNS_TYPE_PKEY:      "pkey_",
		enums.GNS_TYPE_EDKEY:     "edkey_",
		enums.GNS_TYPE_REDIRECT:  "redirect_",
		enums.GNS_TYPE_LEHO:      "leho_",
		enums.GNS_TYPE_NICK:      "nick_",
		enums.GNS_TYPE_GNS2DNS:   "gns2dns_",
		enums.GNS_TYPE_BOX:       "box_",
		enums.GNS_TYPE_DNS_A:     "dnsa_",
		enums.GNS_TYPE_DNS_AAAA:  "dnsaaaa_",
		enums.GNS_TYPE_DNS_CNAME: "dnscname_",
		enums.GNS_TYPE_DNS_TXT:   "dnstxt_",
		enums.GNS_TYPE_DNS_MX:    "dnsmx_",
	}
)

// RRData2Map converts resource record data in to a map
func RRData2Map(t enums.GNSType, buf []byte) (set map[string]string) {
	pf := dlgPrefix[t]
	set = make(map[string]string)
	switch t {
	// Ed25519 public key
	case enums.GNS_TYPE_PKEY,
		enums.GNS_TYPE_EDKEY:
		set[pf+"data"] = util.EncodeBinaryToString(buf)

	// Name string data
	case enums.GNS_TYPE_REDIRECT,
		enums.GNS_TYPE_NICK,
		enums.GNS_TYPE_LEHO,
		enums.GNS_TYPE_DNS_CNAME:
		set[pf+"name"], _ = util.ReadCString(buf, 0)

	// DNS TXT
	case enums.GNS_TYPE_DNS_TXT:
		set[pf+"text"], _ = util.ReadCString(buf, 0)

	// IPv4/IPv6 address
	case enums.GNS_TYPE_DNS_A,
		enums.GNS_TYPE_DNS_AAAA:
		addr := net.IP(buf)
		set[pf+"addr"] = addr.String()

	// DNS MX
	case enums.GNS_TYPE_DNS_MX:
		mx := new(RRmx)
		_ = data.Unmarshal(mx, buf)
		set[pf+"prio"] = util.CastToString(mx.Prio)
		set[pf+"host"], _ = util.ReadCString(mx.Server, 0)

	// BOX
	case enums.GNS_TYPE_BOX:
		// get BOX from data
		box := gns.NewBox(buf)
		set[pf+"proto"] = util.CastToString(box.Proto)
		set[pf+"svc"] = util.CastToString(box.Svc)
		set[pf+"type"] = util.CastToString(box.Type)

		// handle TLSA and SRV cases
		switch box.Type {
		case enums.GNS_TYPE_DNS_TLSA:
			tlsa := new(RRtlsa)
			_ = data.Unmarshal(tlsa, box.RR)
			set[pf+"tlsa_usage"] = util.CastToString(tlsa.Usage)
			set[pf+"tlsa_selector"] = util.CastToString(tlsa.Selector)
			set[pf+"tlsa_match"] = util.CastToString(tlsa.Match)
			set[pf+"tlsa_cert"] = hex.EncodeToString(tlsa.Cert)

		case enums.GNS_TYPE_DNS_SRV:
			set[pf+"srv_host"], _ = util.ReadCString(box.RR, 0)
		}

	// GNS2DNS
	case enums.GNS_TYPE_GNS2DNS:
		list := util.StringList(buf)
		set[pf+"name"] = list[0]
		set[pf+"server"] = list[1]
	}
	return
}

// Map2RRData converts a map to resource record data
func Map2RRData(t enums.GNSType, set map[string]string) (buf []byte, err error) {
	pf := dlgPrefix[t]
	switch t {
	// Ed25519 public key
	case enums.GNS_TYPE_PKEY,
		enums.GNS_TYPE_EDKEY:
		return util.DecodeStringToBinary(set[pf+"data"], 36)

	// Name string data
	case enums.GNS_TYPE_REDIRECT,
		enums.GNS_TYPE_NICK,
		enums.GNS_TYPE_LEHO,
		enums.GNS_TYPE_DNS_CNAME:
		return util.WriteCString(set[pf+"name"]), nil

	// DNS TXT
	case enums.GNS_TYPE_DNS_TXT:
		return util.WriteCString(set[pf+"text"]), nil

	// IPv4/IPv6 address
	case enums.GNS_TYPE_DNS_A,
		enums.GNS_TYPE_DNS_AAAA:
		buf := net.ParseIP(set[pf+"addr"])
		if buf == nil {
			return nil, errors.New("ParseIP failed")
		}
		return buf, nil

	// DNS MX
	case enums.GNS_TYPE_DNS_MX:
		mx := new(RRmx)
		mx.Prio, _ = util.CastFromString[uint16](set[pf+"prio"])
		mx.Server = util.WriteCString(set[pf+"host"])
		return data.Marshal(mx)

	// BOX
	case enums.GNS_TYPE_BOX:
		// assemble box
		box := new(gns.Box)
		box.Proto, _ = util.CastFromString[uint16](set[pf+"proto"])
		box.Svc, _ = util.CastFromString[uint16](set[pf+"svc"])
		box.Type, _ = util.CastFromString[enums.GNSType](set[pf+"type"])

		// handle TLSA and SRV cases
		switch box.Type {
		case enums.GNS_TYPE_DNS_TLSA:
			tlsa := new(RRtlsa)
			tlsa.Usage, _ = util.CastFromString[uint8](set[pf+"tlsa_usage"])
			tlsa.Selector, _ = util.CastFromString[uint8](set[pf+"tlsa_sel"])
			tlsa.Match, _ = util.CastFromString[uint8](set[pf+"tlsa_match"])
			tlsa.Cert, _ = hex.DecodeString(set[pf+"tlsa_cert"])
			box.RR, _ = data.Marshal(tlsa)

		case enums.GNS_TYPE_DNS_SRV:
			box.RR = util.WriteCString(set[pf+"srv_host"])
		}
		return data.Marshal(box)

	// GNS2DNS
	case enums.GNS_TYPE_GNS2DNS:
		buf := util.WriteCString(set[pf+"name"])
		return append(buf, util.WriteCString(set[pf+"server"])...), nil
	}
	return nil, errors.New("unknown RR type")
}

//======================================================================
// Get list of allowed new RRs given a set of existing RRs.
//======================================================================

// Create a list of compatible record types from list of
// existing record types.
func compatibleRR(in []*store.RRData) (out []*store.RRData) {
	for _, t := range rrtypes {
		out = append(out, &store.RRData{
			Type:  t,
			Flags: 0,
		})
	}
	return
}
