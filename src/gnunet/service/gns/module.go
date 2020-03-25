// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
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
	"fmt"
	"strings"

	"gnunet/config"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/concurrent"
	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
)

//======================================================================
// "GNUnet Name System" implementation
//======================================================================

// Error codes
var (
	ErrUnknownTLD           = fmt.Errorf("Unknown TLD in name")
	ErrGNSRecursionExceeded = fmt.Errorf("GNS recursion depth exceeded")
)

//----------------------------------------------------------------------
// Query for simple GNS lookups
//----------------------------------------------------------------------

// Query specifies the context for a basic GNS name lookup of an (atomic)
// label in a given zone identified by its public key.
type Query struct {
	Zone    *ed25519.PublicKey // Public zone key
	Label   string             // Atomic label
	Derived *ed25519.PublicKey // Derived key from (pkey,label)
	Key     *crypto.HashCode   // Key for repository queries (local/remote)
}

// NewQuery assembles a new Query object for the given zone and label.
func NewQuery(pkey *ed25519.PublicKey, label string) *Query {
	// derive a public key from (pkey,label) and set the repository
	// key as the SHA512 hash of the binary key representation.
	pd := crypto.DerivePublicKey(pkey, label, "gns")
	key := crypto.Hash(pd.Bytes())
	return &Query{
		Zone:    pkey,
		Label:   label,
		Derived: pd,
		Key:     key,
	}
}

//----------------------------------------------------------------------
// The GNS module (recursively) resolves GNS names:
// Resolves DNS-like names (e.g. "minecraft.servers.bob.games"; a name is
// a list of labels with '.' as separator) to the requested resource
// records (RRs). In short, the resolution process works as follows:
//
//  Resolve(name):
//  --------------
//  (1) split the name ('.' as separator) into labels in reverse order: labels[]
//  (2) Resolve first label (= root zone, right-most name part, labels[0]) to
//      a zone public key PKEY:
//      (a) the label is a string representation of a public key -> (3)
//      (b) the zone key for the label is stored in the config file -> (3)
//      (c) a local zone with that given label -> (3)
//      (d) ERROR: "Unknown root zone"
//  (3) labels = labels[1:]
//      records = Resolve (labels[0], PKEY)
//      If last label in name: -> (5)
//  (4) for all rec in records:
//          (a) if rec is a PKEY record:
//                  PKEY <- record, --> (3)
//          (b) if rec is a GNS2DNS record:
//                  delegate to DNS to resolve rest of name -> (5)
//          (c) if rec is BOX record:
//                  if rest of name is pattern "_service._proto" and matches
//                  the values in the BOX:
//                      Replace records with resource record from BOX -> (5)
//          (d) if rec is CNAME record:
//                  if no remaining labels:
//                      if requested types include CNAME -> (5)
//                      -> Resolve(CNAME)
//      resolution failed: name not completely processed and no zone available
//
//  (5) return records: it is the responsibility of the caller to assemble
//      the desired result from block data (e.g. filter for requested
//      resource record types).
//----------------------------------------------------------------------

// GNSModule handles the resolution of GNS names to RRs bundled in a block.
type GNSModule struct {
	// Use function references for calls to methods in other modules:
	LookupLocal  func(query *Query) (*message.GNSBlock, error)
	StoreLocal   func(block *message.GNSBlock) error
	LookupRemote func(query *Query) (*message.GNSBlock, error)

	sig *concurrent.Signaller // shared signalling channel
}

// Resolve a GNS name with multiple labels. If pkey is not nil, the name
// is interpreted as "relative to current zone".
func (gns *GNSModule) Resolve(
	path string,
	pkey *ed25519.PublicKey,
	kind RRTypeList,
	mode int,
	depth int) (set *message.GNSRecordSet, err error) {

	// check for recursion depth
	if depth > config.Cfg.GNS.MaxDepth {
		return nil, ErrGNSRecursionExceeded
	}
	// get the labels in reverse order
	names := util.ReverseStringList(strings.Split(path, "."))
	logger.Printf(logger.DBG, "[gns] Resolver called for %v\n", names)

	// check for relative path
	if pkey != nil {
		//resolve relative path
		return gns.ResolveRelative(names, pkey, kind, mode, depth)
	}
	// resolve absolute path
	return gns.ResolveAbsolute(names, kind, mode, depth)
}

// Resolve a fully qualified GNS absolute name (with multiple labels).
func (gns *GNSModule) ResolveAbsolute(
	labels []string,
	kind RRTypeList,
	mode int,
	depth int) (set *message.GNSRecordSet, err error) {

	// get the zone key for the TLD
	pkey := gns.GetZoneKey(labels[0])
	if pkey == nil {
		// we can't resolve this TLD
		err = ErrUnknownTLD
		return
	}
	// continue with resolution relative to a zone.
	return gns.ResolveRelative(labels[1:], pkey, kind, mode, depth)
}

// Resolve relative path (to a given zone) recursively by processing simple
// (PKEY,Label) lookups in sequence and handle intermediate GNS record types
func (gns *GNSModule) ResolveRelative(
	labels []string,
	pkey *ed25519.PublicKey,
	kind RRTypeList,
	mode int,
	depth int) (set *message.GNSRecordSet, err error) {

	// Process all names in sequence
	var (
		records []*message.GNSResourceRecord // final resource records from resolution
		hdlrs   *BlockHandlerList            // list of block handlers in final step
	)
	for ; len(labels) > 0; labels = labels[1:] {
		logger.Printf(logger.DBG, "[gns] ResolveRelative '%s' in '%s'\n", labels[0], util.EncodeBinaryToString(pkey.Bytes()))

		// resolve next level
		var block *message.GNSBlock
		if block, err = gns.Lookup(pkey, labels[0], mode); err != nil {
			// failed to resolve name
			return
		}
		// set new mode after processing right-most label in LOCAL_MASTER mode
		if mode == enums.GNS_LO_LOCAL_MASTER {
			// if we have no results at this point, return NXDOMAIN
			if block == nil {
				// return record set with no entries as signal for NXDOMAIN
				set = message.NewGNSRecordSet()
				return
			}
			mode = enums.GNS_LO_DEFAULT
		}
		// signal NO_DATA if no block is found
		if block == nil {
			return
		}
		// post-process block by inspecting contained resource records for
		// special GNS types
		if records, err = block.Records(); err != nil {
			return
		}
		// assemble a list of block handlers for this block: if multiple
		// block handlers are present, they are consistent with all block
		// records.
		if hdlrs, records, err = NewBlockHandlerList(records, labels[1:]); err != nil {
			// conflicting block handler records found: terminate with error.
			// (N.B.: The BlockHandlerList class executes the logic which mix
			// of resource records in a single block is considered valid.)
			return
		}

		//--------------------------------------------------------------
		// handle special block cases in priority order:
		//--------------------------------------------------------------

		if hdlr := hdlrs.GetHandler(enums.GNS_TYPE_PKEY); hdlr != nil {
			// (1) PKEY record:
			inst := hdlr.(*PkeyHandler)
			// if labels are pending, set new zone and continue resolution;
			// otherwise resolve "@" label for the zone if no PKEY record
			// was requested.
			pkey = inst.pkey
			if len(labels) == 1 && !kind.HasType(enums.GNS_TYPE_PKEY) {
				labels = append(labels, "@")
			}
		} else if hdlr := hdlrs.GetHandler(enums.GNS_TYPE_GNS2DNS); hdlr != nil {
			// (2) GNS2DNS records
			inst := hdlr.(*Gns2DnsHandler)
			// if we are at the end of the path and the requested type
			// includes GNS_TYPE_GNS2DNS, the GNS2DNS records are returned...
			if len(labels) == 1 && kind.HasType(enums.GNS_TYPE_GNS2DNS) && !kind.IsAny() {
				records = inst.recs
				break
			}
			// ... otherwise we need to handle delegation to DNS: returns a
			// list of found resource records in DNS (filter by 'kind')
			lbls := strings.Join(util.ReverseStringList(labels[1:]), ".")
			if len(lbls) > 0 {
				lbls += "."
			}
			fqdn := lbls + inst.Query
			if set, err = gns.ResolveDNS(fqdn, inst.Servers, kind, pkey, depth); err != nil {
				logger.Println(logger.ERROR, "[gns] GNS2DNS resolution failed.")
				return
			}
			// add synthetic LEHO record if we have results and are at the
			// end of the name (labels).
			if len(set.Records) > 0 && len(labels) == 1 {
				// add LEHO supplemental record: The TTL of the new record is
				// the longest-living record in the current set.
				expires := util.AbsoluteTimeNow()
				for _, rec := range set.Records {
					if rec.Expires.Compare(expires) > 0 {
						expires = rec.Expires
					}
				}
				set.Records = append(set.Records, gns.newLEHORecord(inst.Query, expires))
			}
			// we are done with resolution; pass on records to caller
			records = set.Records
			break
		} else if hdlr := hdlrs.GetHandler(enums.GNS_TYPE_BOX); hdlr != nil {
			// (3) BOX records:
			inst := hdlr.(*BoxHandler)
			new_records := inst.Records(kind).Records
			if len(new_records) > 0 {
				records = new_records
				break
			}
		} else if hdlr := hdlrs.GetHandler(enums.GNS_TYPE_DNS_CNAME); hdlr != nil {
			// (4) CNAME records:
			inst := hdlr.(*CnameHandler)
			// if we are at the end of the path and the requested type
			// includes GNS_TYPE_DNS_CNAME, the records are returned...
			if len(labels) == 1 && kind.HasType(enums.GNS_TYPE_DNS_CNAME) && !kind.IsAny() {
				logger.Println(logger.DBG, "[gns] CNAME requested.")
				break
			}
			logger.Println(logger.DBG, "[gns] CNAME resolution required.")
			if set, err = gns.ResolveUnknown(inst.name, labels, pkey, kind, depth+1); err != nil {
				logger.Println(logger.ERROR, "[gns] CNAME resolution failed.")
				return
			}
			// we are done with resolution; pass on records to caller
			records = set.Records
			break
		}
	}
	// Assemble resulting resource record set by filtering for requested types.
	// Records might get transformed by active block handlers.
	set = message.NewGNSRecordSet()
	for _, rec := range records {
		// is this the record type we are looking for?
		if kind.HasType(int(rec.Type)) {
			// add it to the result
			if rec = hdlrs.FinalizeRecord(rec); rec != nil {
				set.AddRecord(rec)
			}
		}
	}

	// if no records of the requested type (either A or AAAA) have been found,
	// and we have a VPN record, return this instead.
	if set.Count == 0 && (kind.HasType(enums.GNS_TYPE_DNS_A) || kind.HasType(enums.GNS_TYPE_DNS_AAAA)) {
		// check for VPN record
		if hdlr := hdlrs.GetHandler(enums.GNS_TYPE_VPN); hdlr != nil {
			// add VPN record to result set
			inst := hdlr.(*VpnHandler)
			set.AddRecord(inst.rec)
		}
	}

	// if the result set is not empty, add all supplemental records we are not
	// asking for explicitly.
	if set.Count > 0 {
		for _, rec := range records {
			if !kind.HasType(int(rec.Type)) && (int(rec.Flags)&enums.GNS_FLAG_SUPPL) != 0 {
				set.AddRecord(rec)
			}
		}
	}
	return
}

// ResolveUnknown resolves a name either in GNS (if applicable) or DNS:
// If the name is a relative GNS path (ending in ".+"), it is resolved in GNS
// relative to the zone PKEY. If the name is an absolute GNS name (ending in
// a PKEY TLD), it is also resolved with GNS. All other names are resolved
// via DNS queries.
func (gns *GNSModule) ResolveUnknown(
	name string,
	labels []string,
	pkey *ed25519.PublicKey,
	kind RRTypeList,
	depth int) (set *message.GNSRecordSet, err error) {

	// relative GNS-based server name?
	if strings.HasSuffix(name, ".+") {
		// resolve server name relative to current zone
		name = strings.TrimSuffix(name, ".+")
		for _, label := range util.ReverseStringList(labels) {
			name += "." + label
		}
		if set, err = gns.Resolve(name, pkey, kind, enums.GNS_LO_DEFAULT, depth+1); err != nil {
			return
		}
	} else {
		// check for absolute GNS name (with PKEY as TLD)
		if zk := gns.GetZoneKey(name); zk != nil {
			// resolve absolute GNS name (name ends in a PKEY)
			if set, err = gns.Resolve(util.StripPathRight(name), zk, kind, enums.GNS_LO_DEFAULT, depth+1); err != nil {
				return
			}
		} else {
			// resolve the server name via DNS
			if set = QueryDNS(util.NextID(), name, nil, kind); set == nil {
				err = ErrNoDNSResults
			}
		}
	}
	return
}

// GetZoneKey returns the PKEY (or nil) from an absolute GNS path.
func (gns *GNSModule) GetZoneKey(path string) *ed25519.PublicKey {
	labels := util.ReverseStringList(strings.Split(path, "."))
	if len(labels[0]) == 52 {
		if data, err := util.DecodeStringToBinary(labels[0], 32); err == nil {
			if pkey := ed25519.NewPublicKeyFromBytes(data); pkey != nil {
				return pkey
			}
		}
	}
	return nil
}

// Lookup name in GNS.
func (gns *GNSModule) Lookup(
	pkey *ed25519.PublicKey,
	label string,
	mode int) (block *message.GNSBlock, err error) {

	// create query (lookup key)
	query := NewQuery(pkey, label)

	// try local lookup first
	if block, err = gns.LookupLocal(query); err != nil {
		logger.Printf(logger.ERROR, "[gns] local Lookup: %s\n", err.Error())
		block = nil
		return
	}
	if block == nil {
		if mode == enums.GNS_LO_DEFAULT {
			// get the block from a remote lookup
			if block, err = gns.LookupRemote(query); err != nil || block == nil {
				if err != nil {
					logger.Printf(logger.ERROR, "[gns] remote Lookup: %s\n", err.Error())
					block = nil
				} else {
					logger.Println(logger.DBG, "[gns] remote Lookup: no block found")
				}
				// lookup fails completely -- no result
				return
			}
			// store RRs from remote locally.
			gns.StoreLocal(block)
		}
	}
	return
}

// newLEHORecord creates a new supplemental GNS record of type LEHO.
func (gns *GNSModule) newLEHORecord(name string, expires util.AbsoluteTime) *message.GNSResourceRecord {
	rr := new(message.GNSResourceRecord)
	rr.Expires = expires
	rr.Flags = uint32(enums.GNS_FLAG_SUPPL)
	rr.Type = uint32(enums.GNS_TYPE_LEHO)
	rr.Size = uint32(len(name) + 1)
	rr.Data = make([]byte, rr.Size)
	copy(rr.Data, []byte(name))
	rr.Data[len(name)] = 0
	return rr
}
