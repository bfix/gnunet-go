package gns

import (
	"fmt"
	"net"
	"strings"
	"time"

	"gnunet/enums"
	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
	"github.com/miekg/dns"
)

// Error codes
var (
	ErrDNSTimedOut  = fmt.Errorf("DNS query timed out")
	ErrNoDNSQueries = fmt.Errorf("No valid DNS queries")
	ErrNoDNSResults = fmt.Errorf("No valid DNS results")
)

// Convert DNS name from its binary representation [RFC1034]:
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

func QueryDNS(id int, name string, server net.IP, kind RRTypeList) *GNSRecordSet {
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
		dns.Fqdn(name),
		dns.TypeANY,
		dns.ClassINET,
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
		set := NewGNSRecordSet()
		for _, record := range in.Answer {
			// check if answer record is of requested type
			if kind.HasType(int(record.Header().Rrtype)) {
				// get wire-format of resource record
				buf := make([]byte, 2048)
				n, err := dns.PackRR(record, buf, 0, nil, false)
				if err != nil {
					logger.Printf(logger.WARN, "[dns][%d] Failed to get RR data for %s\n", id, err.Error())
					continue
				}

				// create a new GNS resource record
				rr := new(message.GNSResourceRecord)
				expires := time.Now().Add(time.Duration(record.Header().Ttl) * time.Second)
				rr.Expires = util.NewAbsoluteTime(expires)
				rr.Flags = 0
				rr.Type = uint32(record.Header().Rrtype)
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

// ResolveDNS resolves a name in DNS. Multiple DNS servers are queried in
// parallel; the first result delivered by any of the servers is returned
// as the result list of matching resource records.
func (gns *GNSModule) ResolveDNS(name string, servers []string, kind RRTypeList, pkey *ed25519.PublicKey) (set *GNSRecordSet, err error) {
	logger.Printf(logger.DBG, "[dns] Resolution of '%s' starting...\n", name)

	// start DNS queries concurrently
	res := make(chan *GNSRecordSet)
	running := 0
	for _, srv := range servers {
		// check if srv is an IPv4/IPv6 address
		addr := net.ParseIP(srv)
		logger.Printf(logger.DBG, "ParseIP('%s', len=%d) --> %v\n", srv, len(srv), addr)
		if addr == nil {
			// no, it is a name... try to resolve an IP address from the name
			query := NewRRTypeList(enums.GNS_TYPE_DNS_A, enums.GNS_TYPE_DNS_AAAA)
			if set, err = gns.ResolveUnknown(srv, pkey, query); err != nil {
				logger.Printf(logger.ERROR, "[dns] Can't resolve NS server '%s': %s\n", srv, err.Error())
				continue
			}
			// traverse resource records for 'A' and 'AAAA' records.
		rec_loop:
			for _, rec := range set.Records {
				switch int(rec.Type) {
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
	timeout := time.Tick(10 * time.Second)
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

		case <-timeout:
			// no results
			logger.Println(logger.WARN, "[dns] Queries timed out.")
			return nil, ErrNoDNSResults
		}
	}
}
