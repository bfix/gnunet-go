package gns

import (
	"encoding/hex"
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

	// Post-process a record: handler can modify/replace a resource
	// record based on their own logic (e.g. BOX)
	PostProcess(*message.GNSResourceRecord) *message.GNSResourceRecord
}

//----------------------------------------------------------------------
// Manage list of block handlers
// Under normal circumstances there is only one (or none) block handler
// per block, but future constructs may allow multiple block handlers
// to be present. The block handler list implements the BlockHandler
// interface.
//----------------------------------------------------------------------

// BlockHandlerList is a list of block handlers instantiated.
type BlockHandlerList struct {
	list map[string]BlockHandler
	keys []string
}

// NewBlockHandlerList instantiates an empty list of block handlers.
func NewBlockHandlerList() *BlockHandlerList {
	return &BlockHandlerList{
		list: make(map[string]BlockHandler),
		keys: make([]string, 0),
	}
}

// GetHandler returns a BlockHandler for the given key. If no block handler exists
// under the given name, a new one is created and stored in the list. The type of
// the new block handler is derived from the key value.
func (hl *BlockHandlerList) GetHandler(key string, create bool) (hdlr BlockHandler) {
	// return handler for given key if it exists
	var ok bool
	if hdlr, ok = hl.list[key]; ok {
		return
	}
	if !create {
		return nil
	}
	// create a new one
	switch key {
	case "pkey":
		hdlr = NewPkeyHandler()
	case "gns2dns":
		hdlr = NewGns2DnsHandler()
	case "box":
		hdlr = NewBoxHandler()
	}
	hl.list[key] = hdlr
	return hdlr
}

// TypeAction of the handler list: If any active block handler...
// * ... rejects a record, it gets finally rejected.
// * ... ignores a record, it will be ignored if no other handler rejects it.
func (hl *BlockHandlerList) TypeAction(t int) int {
	rc := 1
	for _, hdlr := range hl.list {
		switch hdlr.TypeAction(t) {
		case -1:
			return -1
		case 0:
			rc = 0
		}
	}
	return rc
}

// PostProcess a record
func (hl *BlockHandlerList) PostProcess(rec *message.GNSResourceRecord) *message.GNSResourceRecord {
	// Post-process the record through all handlers. Usually no two handlers
	// post-process the same record, but it is not possible to do so. The
	// sequence of post-processing is determined by the sequence
	for _, key := range hl.keys {
		hdlr := hl.list[key]
		rec = hdlr.PostProcess(rec)
	}
	return rec
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
func (h *PkeyHandler) TypeAction(t int) int {
	// everything else is not allowed
	return -1
}

// PostProcess a record
func (h *PkeyHandler) PostProcess(rec *message.GNSResourceRecord) *message.GNSResourceRecord {
	// no post-processing required
	return rec
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
// is to be treated (see BlockHandler interface)
func (h *Gns2DnsHandler) TypeAction(t int) int {
	// only process other GNS2DNS records
	if t == enums.GNS_TYPE_GNS2DNS {
		return 1
	}
	// skip everything else
	return 0
}

// PostProcess a record
func (h *Gns2DnsHandler) PostProcess(rec *message.GNSResourceRecord) *message.GNSResourceRecord {
	// no post-processing required
	return rec
}

// AddRequest adds the DNS request for "name" at "server" to the list
// of requests. All GNS2DNS records must query for the same name
func (h *Gns2DnsHandler) AddRequest(name, server string) bool {
	if len(h.Servers) == 0 {
		h.Name = name
	}
	if name != h.Name {
		return false
	}
	h.Servers = append(h.Servers, server)
	return true
}

//----------------------------------------------------------------------
// BOX handler
//----------------------------------------------------------------------

// BoxHandler implementing the BlockHandler interface
type BoxHandler struct {
	boxes map[string]*Box
}

// NewBoxHandler returns a new BlockHandler instance
func NewBoxHandler() *BoxHandler {
	return &BoxHandler{
		boxes: make(map[string]*Box),
	}
}

// TypeAction return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *BoxHandler) TypeAction(t int) int {
	// process record
	return 1
}

// PostProcess a record
func (h *BoxHandler) PostProcess(rec *message.GNSResourceRecord) *message.GNSResourceRecord {
	// check for boxed record
	if int(rec.Type) == enums.GNS_TYPE_BOX {
		// locate the BOX for the record (that has been validated before)
		key := hex.EncodeToString(rec.Data[:8])
		if box, ok := h.boxes[key]; ok {
			// valid box found: assemble new resource record.
			rr := new(message.GNSResourceRecord)
			rr.Expires = rec.Expires
			rr.Flags = rec.Flags
			rr.Type = box.Type
			rr.Size = uint32(len(box.RR))
			rr.Data = box.RR
			return rr
		}
	}
	return rec
}

// AddBox adds the BOX instance to the handler
func (h *BoxHandler) AddBox(box *Box) {
	h.boxes[box.key] = box
}

//======================================================================
// List of resource records types (for GNS/DNS queries)
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
