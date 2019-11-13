package gns

import (
	"fmt"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
)

var (
	ErrBlockNotDecrypted = fmt.Errorf("GNS block not decrypted")
)

//======================================================================
// GNS block: An encrypted and signed container for GNS resource records
// that represents the "atomic" data structure associated with a GNS
// label in a given zone.
//======================================================================

// SignedBlockData: signed and encrypted list of resource records stored
// in a GNSRecordSet
type SignedBlockData struct {
	Purpose *crypto.SignaturePurpose // Size and purpose of signature (8 bytes)
	Expire  util.AbsoluteTime        // Expiration time of the block.
	EncData []byte                   `size:"*"` // encrypted GNSRecordSet

	// transient data (not serialized)
	data []byte // unencrypted GNSRecord set
}

// GNSBlock is the result of GNS lookups for a given label in a zone.
type GNSBlock struct {
	Signature  []byte `size:"64"` // Signature of the block.
	DerivedKey []byte `size:"32"` // Derived key used for signing
	Block      *SignedBlockData

	// transient data (not serialized)
	checked   bool // block integrity checked
	verified  bool // block signature verified (internal)
	decrypted bool // block data decrypted (internal)
}

// String returns the human-readable representation of a GNSBlock
func (b *GNSBlock) String() string {
	return fmt.Sprintf("GNSBlock{Verified=%v,Decrypted=%v,data=[%d]}",
		b.verified, b.decrypted, len(b.Block.EncData))
}

// Records returns the list of resource records in a block.
func (b *GNSBlock) Records() ([]*message.GNSResourceRecord, error) {
	// check if block is decrypted
	if !b.decrypted {
		return nil, ErrBlockNotDecrypted
	}
	// parse block data into record set
	rs := NewGNSRecordSet()
	if err := data.Unmarshal(rs, b.Block.data); err != nil {
		return nil, err
	}
	return rs.Records, nil
}

// Verify the integrity of the block data from a signature.
func (b *GNSBlock) Verify(zoneKey *ed25519.PublicKey, label string) (err error) {
	// Integrity check performed
	b.checked = true

	// verify derived key
	dkey := ed25519.NewPublicKeyFromBytes(b.DerivedKey)
	dkey2 := crypto.DerivePublicKey(zoneKey, label, "gns")
	if !dkey.Q.Equals(dkey2.Q) {
		return fmt.Errorf("Invalid signature key for GNS Block")
	}
	// verify signature
	var (
		sig *ed25519.EcSignature
		buf []byte
		ok  bool
	)
	if sig, err = ed25519.NewEcSignatureFromBytes(b.Signature); err != nil {
		return
	}
	if buf, err = data.Marshal(b.Block); err != nil {
		return
	}
	if ok, err = dkey.EcVerify(buf, sig); err == nil && !ok {
		err = fmt.Errorf("Signature verification failed for GNS block")
	}
	b.verified = true
	return
}

// Decrypt block data with a key/iv combination derived from (PKEY,label)
func (b *GNSBlock) Decrypt(zoneKey *ed25519.PublicKey, label string) (err error) {
	// decrypt payload
	b.Block.data, err = crypto.DecryptBlock(b.Block.EncData, zoneKey, label)
	b.decrypted = true
	return
}

// NewGNSBlock instantiates an empty GNS block
func NewGNSBlock() *GNSBlock {
	return &GNSBlock{
		Signature:  make([]byte, 64),
		DerivedKey: make([]byte, 32),
		Block: &SignedBlockData{
			Purpose: new(crypto.SignaturePurpose),
			Expire:  *new(util.AbsoluteTime),
			EncData: nil,
			data:    nil,
		},
		checked:   false,
		verified:  false,
		decrypted: false,
	}
}

//----------------------------------------------------------------------
// GNSRecordSet
//----------------------------------------------------------------------

// GNSRecordSet ist the GNUnet data structure for a list of resource records
// in a GNSBlock. As part of GNUnet messages, the record set is padded so that
// the binary size of (records||padding) is the smallest power of two.
type GNSRecordSet struct {
	Count   uint32                       `order:"big"`  // number of resource records
	Records []*message.GNSResourceRecord `size:"Count"` // list of resource records
	Padding []byte                       `size:"*"`     // padding
}

// NewGNSRecordSet returns an empty resource record set.
func NewGNSRecordSet() *GNSRecordSet {
	return &GNSRecordSet{
		Count:   0,
		Records: make([]*message.GNSResourceRecord, 0),
		Padding: make([]byte, 0),
	}
}

// AddRecord to append a resource record to the set.
func (rs *GNSRecordSet) AddRecord(rec *message.GNSResourceRecord) {
	rs.Count++
	rs.Records = append(rs.Records, rec)
}

//======================================================================
// GNS blocks with special types (PKEY, GNS2DNS, BOX) require special
// treatment with respect to other resource records with different types
// in the same block. Usually only certain other types (or not at all)
// are allowed and the allowed ones are required to deliver a consistent
// list of resulting resource records back to the caller.
//======================================================================

// BlockHandler interface.
type BlockHandler interface {
	// TypeAction returns a flag indicating how a resource record of a
	// given type is to be treated:
	//   = -1: Record is not allowed (terminates lookup with an error)
	//   =  0: Record is allowed but will be ignored
	//   =  1: Record is allowed and will be processed
	TypeAction(int) int
}

//----------------------------------------------------------------------
// PKEY handler: Only one PKEY as sole record in a block
//----------------------------------------------------------------------

// PkeyHandler implementing the BlockHandler interface
type PkeyHandler struct {
	pkey *ed25519.PublicKey
}

// NewPkeyHandler returns a new BlockHandler instance
func NewPkeyHandler() *PkeyHandler {
	return &PkeyHandler{
		pkey: nil,
	}
}

// TypeAction return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (m *PkeyHandler) TypeAction(t int) int {
	// everything else is not allowed
	return -1
}

//----------------------------------------------------------------------
// GNS2DNS handler
//----------------------------------------------------------------------

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

//======================================================================
// Lost of resource records types
//======================================================================

// RRTypeList is a list of integers representing RR types.
type RRTypeList []int

// Initialize a new type list with given type values
func NewRRTypeList(args ...int) (res RRTypeList) {
	for _, val := range args {
		// if GNS_TYPE_ANY is encountered, it becomes the sole type
		if val == enums.GNS_TYPE_ANY {
			res = make(RRTypeList, 1)
			res[0] = val
			return
		}
		res = append(res, val)
	}
	return
}

// HasType returns true if the type is included in the list
func (tl RRTypeList) HasType(t int) bool {
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
