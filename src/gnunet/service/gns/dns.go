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
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
	"github.com/miekg/dns"
)

// Error codes
var (
	ErrDNSTimedOut  = fmt.Errorf("query timed out (DNS)")
	ErrNoDNSQueries = fmt.Errorf("no valid DNS queries")
	ErrNoDNSResults = fmt.Errorf("no valid DNS results")
)

//----------------------------------------------------------------------
// List of resource records types (for GNS/DNS queries)
//----------------------------------------------------------------------

// RRTypeList is a list of integers representing RR types.
type RRTypeList []enums.GNSType

// NewRRTypeList initializes a new type list with given type values
func NewRRTypeList(args ...enums.GNSType) (res RRTypeList) {
	for _, val := range args {
		// if GNS_TYPE_ANY is encountered, it becomes the sole type
		if val == enums.GNS_TYPE_ANY {
			res = make(RRTypeList, 1)
			res[0] = val
			return
		}
		res = append(res, val)
	}
	// if no types are passed, mode ANY is set.
	if len(res) == 0 {
		res = make(RRTypeList, 1)
		res[0] = enums.GNS_TYPE_ANY
		return
	}
	return
}

// IsAny returns true if no type is filtered.
func (tl RRTypeList) IsAny() bool {
	return tl[0] == enums.GNS_TYPE_ANY
}

// HasType returns true if the type is included in the list
func (tl RRTypeList) HasType(t enums.GNSType) bool {
	// return true if type is GNS_TYPE_ANY
	if tl[0] == enums.GNS_TYPE_ANY {
		return true
	}
	// check for type in list
	for _, val := range tl {
		if val == t {
			return true
		}
	}
	return false
}

//----------------------------------------------------------------------
// Helper functions
//----------------------------------------------------------------------

// DNSNameFromBytes converts DNS name from its binary representation [RFC1034]:
// A string is a sequence of a (len,chars...) tupels terminated by a (len=0,).
// The name parts are concatenated with "." as separator.
// The parsing starts at offset in the byte array; the function returns the
// offset after the parsed name as well as the name itself.
func DNSNameFromBytes(b []byte, offset int) (int, string) {
	if offset >= len(b) {
		return offset, ""
	}
	str := ""
	pos := offset
	for b[pos] != 0 {
		if len(str) > 0 {
			str += "."
		}
		count := int(b[pos])
		pos++
		str += string(b[pos : pos+count])
		pos += count
	}
	return pos + 1, str
}

// QueryDNS queries the specified DNS server for a given name and expected result types.
func QueryDNS(id int, name string, server net.IP, kind RRTypeList) *message.RecordSet {
	// get default nameserver if not defined.
	if server == nil {
		server = net.IPv4(8, 8, 8, 8)
	}
	logger.Printf(logger.DBG, "[dns][%d] Starting query for '%s' on '%s'...\n", id, name, server.String())

	// assemble query
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     true,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qtype:  dns.TypeANY,
		Qclass: dns.ClassINET,
	}

	// perform query in retry-loop
	for retry := 0; retry < 5; retry++ {
		// send query with new ID when retrying
		m.Id = dns.Id()
		in, err := dns.Exchange(m, net.JoinHostPort(server.String(), "53"))
		// handle DNS fails
		if err != nil {
			errMsg := err.Error()
			if strings.HasSuffix(errMsg, "i/o timeout") {
				logger.Printf(logger.WARN, "[dns][%d] Query timed-out -- retrying (%d/5)\n", id, retry+1)
				continue
			}
			logger.Printf(logger.ERROR, "[dns][%d] Error: %s\n", id, errMsg)
			return nil
		}
		// process results
		logger.Printf(logger.WARN, "[dns][%d] Response from DNS server received (%d/5).\n", id, retry+1)
		if in == nil {
			logger.Printf(logger.ERROR, "[dns][%d] No results\n", id)
			return nil
		}
		set := message.NewRecordSet()
		for _, record := range in.Answer {
			// check if answer record is of requested type
			if kind.HasType(enums.GNSType(record.Header().Rrtype)) {
				// get wire-format of resource record
				buf := make([]byte, 2048)
				n, err := dns.PackRR(record, buf, 0, nil, false)
				if err != nil {
					logger.Printf(logger.WARN, "[dns][%d] Failed to get RR data for %s\n", id, err.Error())
					continue
				}

				// create a new GNS resource record
				rr := new(message.ResourceRecord)
				expires := time.Now().Add(time.Duration(record.Header().Ttl) * time.Second)
				rr.Expire = util.NewAbsoluteTime(expires)
				rr.Flags = 0
				rr.RType = uint32(record.Header().Rrtype)
				rr.Size = uint32(record.Header().Rdlength)
				rr.Data = make([]byte, rr.Size)

				if n < int(rr.Size) {
					logger.Printf(logger.WARN, "[dns][%d] Not enough data in RR (%d != %d)\n", id, n, rr.Size)
					continue
				}
				copy(rr.Data, buf[n-int(rr.Size):])
				set.AddRecord(rr)
			}
		}
		logger.Printf(logger.INFO, "[dns][%d] %d resource records extracted from response (%d/5).\n", id, set.Count, retry+1)
		return set
	}
	logger.Printf(logger.WARN, "[dns][%d] Resolution failed -- giving up...\n", id)
	return nil
}

//----------------------------------------------------------------------
// GNSModule methods
//----------------------------------------------------------------------

// ResolveDNS resolves a name in DNS. Multiple DNS servers are queried in
// parallel; the first result delivered by any of the servers is returned
// as the result list of matching resource records.
func (m *Module) ResolveDNS(
	ctx context.Context,
	name string,
	servers []string,
	kind RRTypeList,
	zkey *crypto.ZoneKey,
	depth int) (set *message.RecordSet, err error) {

	// start DNS queries concurrently
	logger.Printf(logger.DBG, "[dns] Resolution of '%s' starting...\n", name)
	res := make(chan *message.RecordSet)
	running := 0
	for _, srv := range servers {
		// check if srv is an IPv4/IPv6 address
		addr := net.ParseIP(srv)
		logger.Printf(logger.DBG, "ParseIP('%s', len=%d) --> %v\n", srv, len(srv), addr)
		if addr == nil {
			// no, it is a name... try to resolve an IP address from the name
			query := NewRRTypeList(enums.GNS_TYPE_DNS_A, enums.GNS_TYPE_DNS_AAAA)
			if set, err = m.ResolveUnknown(ctx, srv, nil, zkey, query, depth+1); err != nil {
				logger.Printf(logger.ERROR, "[dns] Can't resolve NS server '%s': %s\n", srv, err.Error())
				continue
			}
			// traverse resource records for 'A' and 'AAAA' records.
		rec_loop:
			for _, rec := range set.Records {
				switch enums.GNSType(rec.RType) {
				case enums.GNS_TYPE_DNS_AAAA:
					addr = net.IP(rec.Data)
					// we prefer IPv6
					break rec_loop
				case enums.GNS_TYPE_DNS_A:
					addr = net.IP(rec.Data)
				}
			}
			// check if we have an IP address available
			if addr == nil {
				logger.Printf(logger.WARN, "[dns] No IP address for nameserver '%s'\n", srv)
				continue
			}
		}
		// query DNS concurrently
		go func() {
			res <- QueryDNS(util.NextID(), name, addr, kind)
		}()
		running++
	}
	// check if we started some queries at all.
	if running == 0 {
		return nil, ErrNoDNSQueries
	}
	// wait for query results
	timeout := time.NewTicker(10 * time.Second)
	for {
		select {
		case set = <-res:
			running--
			if set != nil {
				// we have a result.
				logger.Println(logger.DBG, "[dns] Query result available.")
				return
			}
			if running == 0 {
				// no results
				logger.Println(logger.WARN, "[dns] No results received from queries.")
				return nil, ErrNoDNSResults
			}

		case <-timeout.C:
			// no results
			logger.Println(logger.WARN, "[dns] Queries timed out.")
			return nil, ErrNoDNSResults
		}
	}
}
