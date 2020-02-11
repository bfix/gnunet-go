package message

import (
	"fmt"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

var (
	ErrBlockNotDecrypted = fmt.Errorf("GNS block not decrypted")
)

//----------------------------------------------------------------------
// GNS_LOOKUP
//----------------------------------------------------------------------

// GNSLookupMsg
type GNSLookupMsg struct {
	MsgSize  uint16 `order:"big"` // total size of message
	MsgType  uint16 `order:"big"` // GNS_LOOKUP (500)
	Id       uint32 `order:"big"` // Unique identifier for this request (for key collisions).
	Zone     []byte `size:"32"`   // Zone that is to be used for lookup
	Options  uint16 `order:"big"` // Local options for where to look for results
	Reserved uint16 `order:"big"` // Always 0
	Type     uint32 `order:"big"` // the type of record to look up
	Name     []byte `size:"*"`    // zero-terminated name to look up
}

// NewGNSLookupMsg creates a new default message.
func NewGNSLookupMsg() *GNSLookupMsg {
	return &GNSLookupMsg{
		MsgSize:  48, // record size with no name
		MsgType:  GNS_LOOKUP,
		Id:       0,
		Zone:     make([]byte, 32),
		Options:  uint16(enums.GNS_LO_DEFAULT),
		Reserved: 0,
		Type:     uint32(enums.GNS_TYPE_ANY),
		Name:     nil,
	}
}

// SetName appends the name to lookup to the message
func (m *GNSLookupMsg) SetName(name string) {
	m.Name = util.Clone(append([]byte(name), 0))
	m.MsgSize = uint16(48 + len(m.Name))
}

// GetName returns the name to lookup from the message
func (m *GNSLookupMsg) GetName() string {
	size := len(m.Name)
	if m.Name[size-1] != 0 {
		logger.Println(logger.WARN, "GNS_LOOKUP name not NULL-terminated")
	} else {
		size -= 1
	}
	return string(m.Name[:size])
}

// String returns a human-readable representation of the message.
func (m *GNSLookupMsg) String() string {
	return fmt.Sprintf(
		"GNSLookupMsg{Id=%d,Zone=%s,Options=%d,Type=%d,Name=%s}",
		m.Id, util.EncodeBinaryToString(m.Zone),
		m.Options, m.Type, m.GetName())
}

// Header returns the message header in a separate instance.
func (msg *GNSLookupMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// GNS_LOOKUP_RESULT
//----------------------------------------------------------------------

// GNSRecordSet ist the GNUnet data structure for a list of resource records
// in a GNSBlock. As part of GNUnet messages, the record set is padded so that
// the binary size of (records||padding) is the smallest power of two.
type GNSRecordSet struct {
	Count   uint32               `order:"big"`  // number of resource records
	Records []*GNSResourceRecord `size:"Count"` // list of resource records
	Padding []byte               `size:"*"`     // padding
}

// NewGNSRecordSet returns an empty resource record set.
func NewGNSRecordSet() *GNSRecordSet {
	return &GNSRecordSet{
		Count:   0,
		Records: make([]*GNSResourceRecord, 0),
		Padding: make([]byte, 0),
	}
}

// AddRecord to append a resource record to the set.
func (rs *GNSRecordSet) AddRecord(rec *GNSResourceRecord) {
	rs.Count++
	rs.Records = append(rs.Records, rec)
}

// SignedBlockData: signed and encrypted list of resource records stored
// in a GNSRecordSet
type SignedBlockData struct {
	Purpose *crypto.SignaturePurpose // Size and purpose of signature (8 bytes)
	Expire  util.AbsoluteTime        // Expiration time of the block.
	EncData []byte                   `size:"*"` // encrypted GNSRecordSet

	// transient data (not serialized)
	data []byte // decrypted GNSRecord set
}

// GNSBlock is the result of GNS lookups for a given label in a zone.
// An encrypted and signed container for GNS resource records that represents
// the "atomic" data structure associated with a GNS label in a given zone.
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
func (b *GNSBlock) Records() ([]*GNSResourceRecord, error) {
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

// GNSResourceRecord is the GNUnet-specific representation of resource
// records (not to be confused with DNS resource records).
type GNSResourceRecord struct {
	Expires util.AbsoluteTime // Expiration time for the record
	Size    uint32            `order:"big"` // Number of bytes in 'Data'
	Type    uint32            `order:"big"` // Type of the GNS/DNS record
	Flags   uint32            `order:"big"` // Flags for the record
	Data    []byte            `size:"Size"` // Record data
}

// String returns a human-readable representation of the message.
func (r *GNSResourceRecord) String() string {
	return fmt.Sprintf("GNSResourceRecord{type=%s,expire=%s,flags=%d,size=%d}",
		enums.GNS_TYPE[int(r.Type)], r.Expires, r.Flags, r.Size)
}

// GNSLookupResultMsg
type GNSLookupResultMsg struct {
	MsgSize uint16               `order:"big"`  // total size of message
	MsgType uint16               `order:"big"`  // GNS_LOOKUP_RESULT (501)
	Id      uint32               `order:"big"`  // Unique identifier for this request (for key collisions).
	Count   uint32               `order:"big"`  // The number of records contained in response
	Records []*GNSResourceRecord `size:"Count"` // GNS resource records
}

// NewGNSLookupResultMsg
func NewGNSLookupResultMsg(id uint32) *GNSLookupResultMsg {
	return &GNSLookupResultMsg{
		MsgSize: 12, // Empty result (no records)
		MsgType: GNS_LOOKUP_RESULT,
		Id:      id,
		Count:   0,
		Records: make([]*GNSResourceRecord, 0),
	}
}

// AddRecord adds a GNS resource recordto the response message.
func (m *GNSLookupResultMsg) AddRecord(rec *GNSResourceRecord) error {
	recSize := 20 + int(rec.Size)
	if int(m.MsgSize)+recSize > enums.GNS_MAX_BLOCK_SIZE {
		return fmt.Errorf("gns.AddRecord(): MAX_BLOCK_SIZE reached")
	}
	m.Records = append(m.Records, rec)
	m.MsgSize += uint16(recSize)
	m.Count++
	return nil
}

// String returns a human-readable representation of the message.
func (m *GNSLookupResultMsg) String() string {
	return fmt.Sprintf("GNSLookupResultMsg{Id=%d,Count=%d}", m.Id, m.Count)
}

// Header returns the message header in a separate instance.
func (msg *GNSLookupResultMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}
