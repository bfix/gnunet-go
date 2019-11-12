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

// queryDNS resolves a name on a given nameserver and delivers all matching
// resource record (of type 'kind') to the result channel.
func queryDNS(id int, name string, server net.IP, kind int, res chan *GNSRecordSet) {
	logger.Printf(logger.DBG, "[dns][%d] Starting query for '%s' on '%s'...", id, name, server.String())

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
				logger.Printf(logger.WARN, "[dns][%d] Query timed-out -- retrying (%d/5)", id, retry+1)
				continue
			}
			logger.Printf(logger.ERROR, "[dns][%d] Error: %s", id, errMsg)
			res <- nil
		}
		// process results
		if in == nil {
			logger.Printf(logger.ERROR, "[dns][%d] No results", id)
			res <- nil
			return
		}
		set := NewGNSRecordSet()
		for _, record := range in.Answer {
			// create a new GNS resource record
			rr := new(message.GNSResourceRecord)
			rr.Expires = util.AbsoluteTimeNever()
			rr.Flags = 0
			rr.Type = uint32(record.Header().Rrtype)
			rr.Size = uint32(record.Header().Rdlength)
			rr.Data = make([]byte, rr.Size)

			// get wire-format of resource record
			buf := make([]byte, 2048)
			n, err := dns.PackRR(record, buf, 0, nil, false)
			if err != nil {
				logger.Printf(logger.WARN, "[dns][%d] Failed to get RR data for %s", id, err.Error())
				continue
			}
			if n < int(rr.Size) {
				logger.Printf(logger.WARN, "[dns][%d] Nit enough data in RR (%d != %d)", id, n, rr.Size)
				continue
			}
			copy(rr.Data, buf[n-int(rr.Size):])
			set.AddRecord(rr)
		}
		res <- set
		return
	}
	logger.Printf(logger.WARN, "[dns][%d] Resolution failed -- giving up", id)
	res <- nil
}

// ResolveDNS resolves a name in DNS. Multiple DNS servers are queried in
// parallel; the first result delivered by any of the servers is returned
// as the result list of matching resource records.
func (gns *GNSModule) ResolveDNS(name string, servers []string, kind int, pkey *ed25519.PublicKey) (set *GNSRecordSet, err error) {
	logger.Printf(logger.DBG, "[dns] Resolution of '%s' starting...", name)

	// start DNS queries concurrently
	res := make(chan *GNSRecordSet)
	running := 0
	for idx, srv := range servers {
		// check if srv is an IPv4/IPv6 address
		addr := net.ParseIP(srv)
		if addr == nil {
			// no; resolve server name in GNS
			if strings.HasSuffix(srv, ".+") {
				// resolve server name relative to current zone
				zone := util.EncodeBinaryToString(pkey.Bytes())
				srv = strings.TrimSuffix(srv, ".+")
				set, err = gns.Resolve(srv, pkey, enums.GNS_TYPE_ANY, enums.GNS_LO_DEFAULT)
				if err != nil {
					logger.Printf(logger.ERROR, "[dns] Can't resolve NS server '%s' in '%s'", srv, zone)
					continue
				}
			} else {
				// resolve absolute GNS name (MUST end in a PKEY)
				set, err = gns.Resolve(srv, nil, enums.GNS_TYPE_ANY, enums.GNS_LO_DEFAULT)
				if err != nil {
					logger.Printf(logger.ERROR, "[dns] Can't resolve NS server '%s'", srv)
					continue
				}
			}
			// traverse resource records for 'A' and 'AAAA' records.
		rec_loop:
			for _, rec := range set.Records {
				switch int(rec.Type) {
				case enums.GNS_TYPE_DNS_AAAA:
					addr = net.IP(rec.Data)
					break rec_loop
				case enums.GNS_TYPE_DNS_A:
					addr = net.IP(rec.Data)
				}
			}
		}
		// query DNS concurrently
		go queryDNS(idx, name, addr, kind, res)
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
				return
			}
			if running == 0 {
				// no results
				return nil, ErrNoDNSResults
			}

		case <-timeout:
			// no results
			return nil, ErrNoDNSResults
		}
	}
}
