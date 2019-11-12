package gns

import (
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
// GNS blocks with special types (PKEY, GNS2DNS) require special
// treatment with respect to other resource records with different types
// in the same block. Usually only certain other types (or not at all)
// are allowed and the allowed ones are required to deliver a consistent
// list of resulting resource records passed back to the caller.
//----------------------------------------------------------------------

// BlockHandler interface.
type BlockHandler interface {
	// TypeAction returns a flag indicating how a resource record of a
	// given type is to be treated:
	//   = -1: Record is not allowed (terminates lookup with an error)
	//   =  0: Record is allowed but will be ignored
	//   =  1: Record is allowed and will be processed
	TypeAction(int) int
}

// Gns2DnsHandler implementing the BlockHandler interface
type Gns2DnsHandler struct {
	Name    string
	Servers []string
}

// NewGns2DnsHandler returns a new BlockHandler instance
func NewGns2DnsHandler() *Gns2DnsHandler {
	return &Gns2DnsHandler{
		Name:    "",
		Servers: make([]string, 0),
	}
}

// TypeAction return a flag indicating how a resource record of a given type
// is to be treated (see RecordMaster interface)
func (m *Gns2DnsHandler) TypeAction(t int) int {
	// only process other GNS2DNS records
	if t == enums.GNS_TYPE_GNS2DNS {
		return 1
	}
	// skip everything else
	return 0
}

// AddRequest adds the DNS request for "name" at "server" to the list
// of requests. All GNS2DNS records must query for the same name
func (m *Gns2DnsHandler) AddRequest(name, server string) bool {
	if len(m.Servers) == 0 {
		m.Name = name
	}
	if name != m.Name {
		return false
	}
	m.Servers = append(m.Servers, server)
	return true
}

//----------------------------------------------------------------------
// The GNS module (recursively) resolves GNS names:
// Resolves DNS-like names (e.g. "minecraft.servers.bob.games") to the
// requested resource records (RRs). In short, the resolution process
// works as follows:
//
//  Resolve(name):
//  --------------
//  (1) split the full name into elements in reverse order: names[]
//  (2) Resolve first element (root zone, right-most name part, name[0]) to
//      a zone public key PKEY:
//      (a) the name is a string representation of a public key -> (3)
//      (b) the zone key for the name is stored in the config file -> (3)
//      (c) a local zone with that given name -> (3)
//      (d) ERROR: "Unknown root zone"
//  (3) names = names[1:] // remove first element
//      block = Lookup (PKEY, names[0]):
//      (a) If last element of namess: -> (4)
//      (b) block is PKEY record:
//          PKEY <- block, --> (3)
//  (4) return block: it is the responsibility of the caller to assemble
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

// Resolve a GNS name with multiple elements, If pkey is not nil, the name
// is interpreted as "relative to current zone".
func (gns *GNSModule) Resolve(path string, pkey *ed25519.PublicKey, kind int, mode int) (set *GNSRecordSet, err error) {
	// get the name elements in reverse order
	names := util.ReverseStringList(strings.Split(path, "."))

	// check for relative path
	if pkey != nil {
		//resolve relative path
		return gns.ResolveRelative(names, pkey, kind, mode)
	}
	// resolve absolute path
	return gns.ResolveAbsolute(names, kind, mode)
}

// Resolve a fully qualified GNS absolute name (with multiple levels).
func (gns *GNSModule) ResolveAbsolute(names []string, kind int, mode int) (set *GNSRecordSet, err error) {
	// get the root zone key for the TLD
	var (
		pkey *ed25519.PublicKey
		data []byte
	)
	for {
		// (1) check if TLD is a public key string
		if len(names[0]) == 52 {
			if data, err = util.DecodeStringToBinary(names[0], 32); err == nil {
				if pkey = ed25519.NewPublicKeyFromBytes(data); pkey != nil {
					break
				}
			}
		}
		// (2) check if TLD is in our local config
		if pkey = config.Cfg.GNS.GetRootZoneKey(names[0]); pkey != nil {
			break
		}
		// (3) check if TLD is one of our identities
		if pkey, err = gns.GetLocalZone(names[0]); err == nil {
			break
		}
		// (4) we can't resolve this TLD
		return nil, ErrUnknownTLD
	}
	// continue with resolution relative to a zone.
	return gns.ResolveRelative(names[1:], pkey, kind, mode)
}

// Resolve relative path (to a given zone) recursively by processing simple
// (PKEY,Label) lookups in sequence and handle intermediate GNS record types
func (gns *GNSModule) ResolveRelative(names []string, pkey *ed25519.PublicKey, kind int, mode int) (set *GNSRecordSet, err error) {
	// Process all names in sequence
	var records []*message.GNSResourceRecord
name_loop:
	for ; len(names) > 0; names = names[1:] {
		// resolve next level
		var block *GNSBlock
		if block, err = gns.Lookup(pkey, names[0], mode == enums.GNS_LO_DEFAULT); err != nil {
			// failed to resolve name
			return
		}
		// set new mode after processing right-most label in LOCAL_MASTER mode
		if mode == enums.GNS_LO_LOCAL_MASTER {
			mode = enums.GNS_LO_DEFAULT
		}
		// post-process block by inspecting contained resource records for
		// special GNS types
		var hdlr BlockHandler
		if records, err = block.Records(); err != nil {
			return
		}
		for _, rec := range records {
			// let a block handler decide how to handle records
			if hdlr != nil {
				switch hdlr.TypeAction(int(rec.Type)) {
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
			}
			switch int(rec.Type) {
			//----------------------------------------------------------
			case enums.GNS_TYPE_PKEY:
				// check for single RR and sane key data
				if len(rec.Data) != 32 || len(records) > 1 {
					err = ErrInvalidPKEY
					return
				}
				// set new PKEY and continue resolution
				pkey = ed25519.NewPublicKeyFromBytes(rec.Data)
				continue name_loop

			//----------------------------------------------------------
			case enums.GNS_TYPE_GNS2DNS:
				// get the master controlling this block; create a new
				// one if necessary
				var inst *Gns2DnsHandler
				if hdlr == nil {
					inst = NewGns2DnsHandler()
					hdlr = inst
				} else {
					inst = hdlr.(*Gns2DnsHandler)
				}
				// extract list of names in DATA block:
				dnsNames := util.StringList(rec.Data)
				if len(dnsNames) != 2 {
					err = ErrInvalidRecordBody
					return
				}
				// Add to collection of requests
				if !inst.AddRequest(dnsNames[0], dnsNames[1]) {
					err = ErrInvalidRecordBody
					return
				}
			}
		}
		// handle special block cases
		if hdlr != nil {
			switch inst := hdlr.(type) {
			case *Gns2DnsHandler:
				// we need to handle delegation to DNS: returns a list of found
				// resource records in DNS (filter by 'kind')
				fqdn := strings.Join(util.ReverseStringList(names), ".") + "." + inst.Name
				if set, err = gns.ResolveDNS(fqdn, inst.Servers, kind, pkey); err != nil {
					return
				}
				records = set.Records
			}
		}
	}
	// Assemble resulting resource record set
	set = NewGNSRecordSet()
	for _, rec := range records {
		// is this the record type we are looking for?
		if kind == enums.GNS_TYPE_ANY || int(rec.Type) == kind {
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
		logger.Println(logger.DBG, "[gns] local Lookup: no block found")
		if remote {
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
			gns.StoreLocal(query, block)
		}
	}
	return
}
