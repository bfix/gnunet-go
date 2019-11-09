package gns

import (
	"fmt"
	"strings"

	"gnunet/config"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
)

//======================================================================
// "GNUnet Name System" implementation
//======================================================================

// Error codes
var (
	ErrUnknownTLD = fmt.Errorf("Unknown TLD in name")
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

// Resolve a GNS name with multiple levels by proocessing simple (PKEY,Label)
// lookups in sequence.
func (gns *GNSModule) Resolve(path string, kind int, options int) (block *GNSBlock, err error) {
	// split the full name (path) into elements
	names := util.ReverseStrings(strings.Split(path, "."))

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
	// now we can resolve recursively
	return gns.recursiveResolve(pkey, names[1:], kind, options)
}

// Recursive resolution
func (gns *GNSModule) recursiveResolve(pkey *ed25519.PublicKey, names []string, kind int, options int) (block *GNSBlock, err error) {
	// resolve next level
	if block, err = gns.Lookup(pkey, names[0], kind, options); err != nil {
		// failed to resolve name
		return
	}
	// handle block
	return
}

// Lookup name in GNS.
func (gns *GNSModule) Lookup(pkey *ed25519.PublicKey, label string, kind int, options int) (block *GNSBlock, err error) {

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
		if options == enums.GNS_LO_DEFAULT {
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
