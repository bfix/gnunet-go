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
	"fmt"
	"gnunet/enums"
	"gnunet/service/dht/blocks"
	"gnunet/service/gns/rr"
	"gnunet/service/store"
	"gnunet/util"
	"net"
	"time"

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

//======================================================================
// Convert binary resource records to ParameterSet and vice-versa.
// The map keys must match the HTML names of dialog fields.
//======================================================================

//----------------------------------------------------------------------
// GUI rendering hepers
//----------------------------------------------------------------------

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

// convert GNUnet time to string for HTML
func htmlTime(ts util.AbsoluteTime) string {
	if ts.IsNever() {
		return ""
	}
	return time.UnixMicro(int64(ts.Val)).Format(timeHTML)
}

func parseDuration(s string) uint64 {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 3600000000 // 1 hour default
	}
	return uint64(d.Microseconds())
}

func guiDuration(ts util.AbsoluteTime) string {
	d := time.Duration(ts.Val) * time.Microsecond
	return d.String()
}

func guiTime(ts util.AbsoluteTime) string {
	if ts.IsNever() {
		return "Never"
	}
	return time.UnixMicro(int64(ts.Val)).Format(timeGUI)
}

// convert zone key type to string
func guiKeyType(t enums.GNSType) string {
	switch t {
	case enums.GNS_TYPE_PKEY:
		return "PKEY"
	case enums.GNS_TYPE_EDKEY:
		return "EDKEY"
	}
	return "???"
}

func guiRRdata(t enums.GNSType, buf []byte) string {
	// get record instance
	inst, err := rr.ParseRR(t, buf)
	if err != nil {
		return "(invalid)"
	}
	// type-dependent rendering
	switch rec := inst.(type) {
	case *rr.PKEY:
		return fmt.Sprintf("<span title='public zone key'>%s</span>", rec.ZoneKey.ID())
	case *rr.EDKEY:
		return fmt.Sprintf("<span title='public zone key'>%s</span>", rec.ZoneKey.ID())
	case *rr.REDIRECT:
		return fmt.Sprintf("<span title='redirect target'>%s</span>", rec.Name)
	case *rr.NICK:
		return fmt.Sprintf("<span title='nick name'>%s</span>", rec.Name)
	case *rr.LEHO:
		return fmt.Sprintf("<span title='legacy hostname'>%s</span>", rec.Name)
	case *rr.CNAME:
		return fmt.Sprintf("<span title='canonical name'>%s</span>", rec.Name)
	case *rr.TXT:
		return fmt.Sprintf("<span title='text'>%s</span>", rec.Text)
	case *rr.DNSA:
		return fmt.Sprintf("<span title='IPv4 address'>%s</span>", rec.Addr.String())
	case *rr.DNSAAAA:
		return fmt.Sprintf("<span title='IPv6 address'>%s</span>", rec.Addr.String())
	case *rr.MX:
		s := fmt.Sprintf("<span title='priority'>[%d]</span>&nbsp;", rec.Prio)
		return s + fmt.Sprintf("<span title='server'>%s</span>", rec.Server)
	case *rr.BOX:
		s := fmt.Sprintf("<span title='service'>%s</span>/", rr.GetServiceName(rec.Svc, rec.Proto))
		s += fmt.Sprintf("<span title='protocol'>%s</span> ", rr.GetProtocolName(rec.Proto))
		switch rec.Type {
		case enums.GNS_TYPE_DNS_TLSA:
			tlsa := new(rr.TLSA)
			_ = data.Unmarshal(tlsa, rec.RR)
			s += "TLSA[<br>"
			s += fmt.Sprintf("&#8729;&nbsp;Usage: %s<br>", rr.TLSAUsage[tlsa.Usage])
			s += fmt.Sprintf("&#8729;&nbsp;Selector: %s<br>", rr.TLSASelector[tlsa.Selector])
			s += fmt.Sprintf("&#8729;&nbsp;Match: %s<br>", rr.TLSAMatch[tlsa.Match])
			s += "&#8729;&nbsp;CertData:<br>"
			cert := hex.EncodeToString(tlsa.Cert)
			for len(cert) > 32 {
				s += "&nbsp;&nbsp;" + cert[:32] + "<br>"
				cert = cert[32:]
			}
			s += "&nbsp;&nbsp;" + cert + "<br>]"
			return s
		case enums.GNS_TYPE_DNS_SRV:
			srv, _ := util.ReadCString(rec.RR, 0)
			s += fmt.Sprintf("SRV[ %s ]", srv)
			return s
		}
	case *rr.GNS2DNS:
		s := fmt.Sprintf("<span title='name'>%s</span> (Resolver: ", rec.Name)
		return s + fmt.Sprintf("<span title='server'>%s</span>)", rec.Server)
	}
	return "(unknown)"
}

// get prefix for GUI fields for given RR type
func guiPrefix(t enums.GNSType) string {
	pf, ok := dlgPrefix[t]
	if !ok {
		return ""
	}
	return pf
}

// parse expiration time and flags from GUI parameters
func guiParse(params map[string]string, pf string) (exp util.AbsoluteTime, flags enums.GNSFlag) {
	// parse expiration time
	if _, ok := params[pf+"ttl"]; ok {
		flags |= enums.GNS_FLAG_RELATIVE_EXPIRATION
		exp.Val = parseDuration(params[pf+"ttl_value"])
	} else {
		exp = util.AbsoluteTimeNever()
		if _, ok := params[pf+"never"]; !ok {
			ts, _ := time.Parse(timeHTML, params[pf+"expires"])
			exp.Val = uint64(ts.UnixMicro())
		}
	}
	// parse flags
	flags = 0
	if _, ok := params[pf+"private"]; ok {
		flags |= enums.GNS_FLAG_PRIVATE
	}
	if _, ok := params[pf+"shadow"]; ok {
		flags |= enums.GNS_FLAG_SHADOW
	}
	if _, ok := params[pf+"suppl"]; ok {
		flags |= enums.GNS_FLAG_SUPPLEMENTAL
	}
	if _, ok := params[pf+"critical"]; ok {
		flags |= enums.GNS_FLAG_CRITICAL
	}
	return
}

//----------------------------------------------------------------------
// Convert RR to string-keyed map and vice-versa.
//----------------------------------------------------------------------

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
		mx := new(rr.MX)
		_ = data.Unmarshal(mx, buf)
		set[pf+"prio"] = util.CastToString(mx.Prio)
		set[pf+"host"] = mx.Server

	// BOX
	case enums.GNS_TYPE_BOX:
		// get BOX from data
		box := rr.NewBOX(buf)
		set[pf+"proto"] = util.CastToString(box.Proto)
		set[pf+"svc"] = util.CastToString(box.Svc)
		set[pf+"type"] = util.CastToString(box.Type)

		// handle TLSA and SRV cases
		switch box.Type {
		case enums.GNS_TYPE_DNS_TLSA:
			tlsa := new(rr.TLSA)
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
		mx := new(rr.MX)
		mx.Prio, _ = util.CastFromString[uint16](set[pf+"prio"])
		mx.Server = set[pf+"host"]
		return data.Marshal(mx)

	// BOX
	case enums.GNS_TYPE_BOX:
		// assemble box
		box := new(rr.BOX)
		box.Proto, _ = util.CastFromString[uint16](set[pf+"proto"])
		box.Svc, _ = util.CastFromString[uint16](set[pf+"svc"])
		box.Type, _ = util.CastFromString[enums.GNSType](set[pf+"type"])

		// handle TLSA and SRV cases
		switch box.Type {
		case enums.GNS_TYPE_DNS_TLSA:
			tlsa := new(rr.TLSA)
			tlsa.Usage, _ = util.CastFromString[uint8](set[pf+"tlsa_usage"])
			tlsa.Selector, _ = util.CastFromString[uint8](set[pf+"tlsa_selector"])
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
// ResourceRecord helpers
//======================================================================

// Create a list of compatible record types from list of
// existing record types.
func compatibleRR(in []*enums.GNSSpec, label string) (out []*enums.GNSSpec) {
	for _, t := range rrtypes {
		if ok, forced := rr.CanCoexist(t, in, label); ok {
			out = append(out, &enums.GNSSpec{
				Type:  t,
				Flags: forced,
			})
		}
	}
	return
}

// get a list of resource records for a given label in a zone.
func (zm *ZoneMaster) GetRecordSet(label int64, filter enums.GNSFilter) (rs *blocks.RecordSet, expire util.AbsoluteTime, err error) {
	// collect records for zone label
	var recs []*store.Record
	if recs, err = zm.zdb.GetRecords("lid=%d", label); err != nil {
		return
	}
	// assemble record set and find earliest expiration
	expire = util.AbsoluteTimeNever()
	rs = blocks.NewRecordSet()
	for _, r := range recs {
		// filter out records
		if filter&enums.GNS_FILTER_OMIT_PRIVATE != 0 && r.Flags&enums.GNS_FLAG_PRIVATE != 0 {
			continue
		}
		// skip TTL expiry when determining earliest expiry
		if r.Flags&enums.GNS_FLAG_RELATIVE_EXPIRATION == 0 && r.Expire.Compare(expire) < 0 {
			expire = r.Expire
		}
		rs.AddRecord(&r.ResourceRecord)
	}
	// do not add padding yet as record set may be filtered before use.
	return
}
