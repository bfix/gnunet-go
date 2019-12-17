package gns

import (
	"encoding/hex"
	"fmt"
	"strings"

	"gnunet/config"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
)

//======================================================================
// "GNUnet Name System" implementation
//======================================================================

// Error codes
var (
	ErrUnknownTLD        = fmt.Errorf("Unknown TLD in name")
	ErrInvalidRecordType = fmt.Errorf("Invalid resource record type")
	ErrInvalidRecordBody = fmt.Errorf("Invalid resource record body")
	ErrInvalidPKEY       = fmt.Errorf("Invalid PKEY resource record")
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
//          (b) if rec is a PKEY record:
//                  PKEY <- record, --> (3)
//          (c) if rec is a GNS2DNS record:
//                  delegate to DNS to resolve rest of name -> (5)
//          (d) if rec is BOX record:
//                  if rest of name is pattern "_service._proto" and matches
//                  the values in the BOX:
//                      Replace records with resource record from BOX -> (5)
//      resolution failed: name not completely processed and no zone available
//
//  (5) return records: it is the responsibility of the caller to assemble
//      the desired result from block data (e.g. filter for requested
//      resource record types).
//----------------------------------------------------------------------

// GNSModule handles the resolution of GNS names to RRs bundled in a block.
type GNSModule struct {
	// Use function references for calls to methods in other modules:
	//
	LookupLocal  func(query *Query) (*GNSBlock, error)
	StoreLocal   func(query *Query, block *GNSBlock) error
	LookupRemote func(query *Query) (*GNSBlock, error)
	GetLocalZone func(name string) (*ed25519.PublicKey, error)
}

// Resolve a GNS name with multiple labels. If pkey is not nil, the name
// is interpreted as "relative to current zone".
func (gns *GNSModule) Resolve(path string, pkey *ed25519.PublicKey, kind RRTypeList, mode int) (set *GNSRecordSet, err error) {
	// get the labels in reverse order
	names := util.ReverseStringList(strings.Split(path, "."))
	logger.Printf(logger.DBG, "[gns] Resolver called for %v\n", names)

	// check for relative path
	if pkey != nil {
		//resolve relative path
		return gns.ResolveRelative(names, pkey, kind, mode)
	}
	// resolve absolute path
	return gns.ResolveAbsolute(names, kind, mode)
}

// Resolve a fully qualified GNS absolute name (with multiple labels).
func (gns *GNSModule) ResolveAbsolute(labels []string, kind RRTypeList, mode int) (set *GNSRecordSet, err error) {
	// get the root zone key for the TLD
	var (
		pkey *ed25519.PublicKey
		data []byte
	)
	for {
		// (1) check if TLD is a public key string
		if len(labels[0]) == 52 {
			if data, err = util.DecodeStringToBinary(labels[0], 32); err == nil {
				if pkey = ed25519.NewPublicKeyFromBytes(data); pkey != nil {
					break
				}
			}
		}
		// (2) check if TLD is in our local config
		if pkey = config.Cfg.GNS.GetRootZoneKey(labels[0]); pkey != nil {
			break
		}
		// (3) check if TLD is one of our identities
		if pkey, err = gns.GetLocalZone(labels[0]); err == nil {
			break
		}
		// (4) we can't resolve this TLD
		return nil, ErrUnknownTLD
	}
	// continue with resolution relative to a zone.
	return gns.ResolveRelative(labels[1:], pkey, kind, mode)
}

// Resolve relative path (to a given zone) recursively by processing simple
// (PKEY,Label) lookups in sequence and handle intermediate GNS record types
func (gns *GNSModule) ResolveRelative(labels []string, pkey *ed25519.PublicKey, kind RRTypeList, mode int) (set *GNSRecordSet, err error) {
	// Process all names in sequence
	var (
		records []*message.GNSResourceRecord // final resource records from resolution
		hdlrs   *BlockHandlerList            // list of block handlers in final step
	)
name_loop:
	for ; len(labels) > 0; labels = labels[1:] {
		logger.Printf(logger.DBG, "[gns] ResolveRelative '%s' in '%s'\n", labels[0], util.EncodeBinaryToString(pkey.Bytes()))

		// resolve next level
		var block *GNSBlock
		if block, err = gns.Lookup(pkey, labels[0], mode == enums.GNS_LO_DEFAULT); err != nil {
			// failed to resolve name
			return
		}
		// set new mode after processing right-most label in LOCAL_MASTER mode
		if mode == enums.GNS_LO_LOCAL_MASTER {
			mode = enums.GNS_LO_DEFAULT
		}
		// post-process block by inspecting contained resource records for
		// special GNS types
		if records, err = block.Records(); err != nil {
			return
		}
		// list of block handlers for this block
		hdlrs = NewBlockHandlerList()
		for _, rec := range records {

			// let a block handlers decide how to handle records
			switch hdlrs.TypeAction(int(rec.Type)) {
			case -1:
				// No records of this type allowed in block
				err = ErrInvalidRecordType
				return
			case 0:
				// records of this type are simply ignored
				continue
			case 1:
				// process record of this type
			}

			// Process record based on its type
			switch int(rec.Type) {

			//----------------------------------------------------------
			case enums.GNS_TYPE_PKEY:
				// check for sane key data
				if len(rec.Data) != 32 {
					err = ErrInvalidPKEY
					return
				}
				// set a PKEY handler
				hdlr := hdlrs.GetHandler("pkey").(*PkeyHandler)
				if hdlr.pkey != nil {
					// fails if pkey is already set (from a previous record)
					err = ErrInvalidPKEY
					return
				}
				hdlr.pkey = ed25519.NewPublicKeyFromBytes(rec.Data)
				continue

			//----------------------------------------------------------
			case enums.GNS_TYPE_GNS2DNS:
				// extract list of names in DATA block:
				logger.Printf(logger.DBG, "[gns] GNS2DNS data: %s\n", hex.EncodeToString(rec.Data))
				var dnsNames []string
				for pos := 0; ; {
					next, name := DNSNameFromBytes(rec.Data, pos)
					if len(name) == 0 {
						break
					}
					dnsNames = append(dnsNames, name)
					pos = next
				}
				logger.Printf(logger.DBG, "[gns] GNS2DNS params: %v\n", dnsNames)
				if len(dnsNames) != 2 {
					err = ErrInvalidRecordBody
					return
				}
				// Add to collection of requests
				hdlr := hdlrs.GetHandler("gns2dns").(*Gns2DnsHandler)
				logger.Printf(logger.DBG, "[gns] GNS2DNS: query for '%s' on '%s'\n", dnsNames[0], dnsNames[1])
				if !hdlr.AddRequest(dnsNames[0], dnsNames[1]) {
					err = ErrInvalidRecordBody
					return
				}

			//----------------------------------------------------------
			case enums.GNS_TYPE_BOX:
				// check if we need to process the BOX record:
				// (1) only two remaining labels
				if len(labels) != 3 {
					continue
				}
				// (2) remaining labels must start with '_'
				if labels[1][0] != '_' || labels[2][0] != '_' {
					continue
				}
				// (3) check of "svc" and "proto" match values in the BOX
				box := NewBox(rec.Data)
				if box.Matches(labels[1:]) {
					// get the handler instance and add BOX
					hdlr := hdlrs.GetHandler("box").(*BoxHandler)
					hdlr.AddBox(box)
				}
			}
		}
		// handle special block cases in priority order:
		// (1) PKEY record: continue resolution with new zone
		if hdlr := hdlrs.GetHandler("pkey").(*PkeyHandler); hdlr != nil {
			// PKEY must be sole record in block
			if len(records) > 1 {
				logger.Println(logger.ERROR, "[gns] PKEY with other records not allowed.")
				return nil, ErrInvalidPKEY
			}
			// set new zone and continue
			pkey = hdlr.pkey
			continue name_loop
		}
		// (2) GNS2DNS records: delegate resolution to DNS
		if hdlr := hdlrs.GetHandler("dns2dns").(*Gns2DnsHandler); hdlr != nil {
			// we need to handle delegation to DNS: returns a list of found
			// resource records in DNS (filter by 'kind')
			fqdn := strings.Join(util.ReverseStringList(labels[1:]), ".") + "." + hdlr.Name
			if set, err = gns.ResolveDNS(fqdn, hdlr.Servers, kind, pkey); err != nil {
				logger.Println(logger.ERROR, "[gns] GNS2DNS resolution failed.")
				return
			}
			// we are done with resolution; pass on records to caller
			records = set.Records
			break name_loop
		}
	}
	// Assemble resulting resource record set by filtering for requested types.
	// Records might get transformed by active block handlers.
	set = NewGNSRecordSet()
	for _, rec := range records {
		// allow block handlers to modify/replace a resource record
		rec = hdlrs.PostProcess(rec)
		// is this the record type we are looking for?
		if kind.HasType(int(rec.Type)) {
			// add it to the result
			set.AddRecord(rec)
		}
	}
	return
}

// Lookup name in GNS.
func (gns *GNSModule) Lookup(pkey *ed25519.PublicKey, label string, remote bool) (block *GNSBlock, err error) {

	// create query (lookup key)
	query := NewQuery(pkey, label)

	// try local lookup first
	if block, err = gns.LookupLocal(query); err != nil {
		logger.Printf(logger.ERROR, "[gns] local Lookup: %s\n", err.Error())
		block = nil
		return
	}
	if block == nil {
		if remote {
			// get the block from a remote lookup
			if block, err = gns.LookupRemote(query); err != nil || block == nil {
				if err != nil {
					logger.Printf(logger.ERROR, "[gns] remote Lookup: %s\n", err.Error())
					block = nil
				} else {
					logger.Println(logger.DBG, "[gns] remote Lookup: no block found")
					err = fmt.Errorf("No block found")
				}
				// lookup fails completely -- no result
				return
			}
			// store RRs from remote locally.
			gns.StoreLocal(query, block)
		} else {
			err = fmt.Errorf("No block found")
		}
	}
	return
}
