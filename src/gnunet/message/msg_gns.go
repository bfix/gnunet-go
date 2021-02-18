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

// Error messages
var (
	ErrBlockNotDecrypted = fmt.Errorf("GNS block not decrypted")
)

//----------------------------------------------------------------------
// GNS_LOOKUP
//----------------------------------------------------------------------

// LookupMsg is a request message for a GNS name lookup
type LookupMsg struct {
	MsgSize  uint16 `order:"big"` // total size of message
	MsgType  uint16 `order:"big"` // GNS_LOOKUP (500)
	ID       uint32 `order:"big"` // Unique identifier for this request (for key collisions).
	Zone     []byte `size:"32"`   // Zone that is to be used for lookup
	Options  uint16 `order:"big"` // Local options for where to look for results
	Reserved uint16 `order:"big"` // Always 0
	Type     uint32 `order:"big"` // the type of record to look up
	Name     []byte `size:"*"`    // zero-terminated name to look up
}

// NewGNSLookupMsg creates a new default message.
func NewGNSLookupMsg() *LookupMsg {
	return &LookupMsg{
		MsgSize:  48, // record size with no name
		MsgType:  GNS_LOOKUP,
		ID:       0,
		Zone:     make([]byte, 32),
		Options:  uint16(enums.GNS_LO_DEFAULT),
		Reserved: 0,
		Type:     uint32(enums.GNS_TYPE_ANY),
		Name:     nil,
	}
}

// SetName appends the name to lookup to the message
func (m *LookupMsg) SetName(name string) {
	m.Name = util.Clone(append([]byte(name), 0))
	m.MsgSize = uint16(48 + len(m.Name))
}

// GetName returns the name to lookup from the message
func (m *LookupMsg) GetName() string {
	size := len(m.Name)
	if m.Name[size-1] != 0 {
		logger.Println(logger.WARN, "GNS_LOOKUP name not NULL-terminated")
	} else {
		size--
	}
	return string(m.Name[:size])
}

// String returns a human-readable representation of the message.
func (m *LookupMsg) String() string {
	return fmt.Sprintf(
		"GNSLookupMsg{Id=%d,Zone=%s,Options=%d,Type=%d,Name=%s}",
		m.ID, util.EncodeBinaryToString(m.Zone),
		m.Options, m.Type, m.GetName())
}

// Header returns the message header in a separate instance.
func (m *LookupMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

//----------------------------------------------------------------------
// GNS_LOOKUP_RESULT
//----------------------------------------------------------------------

// RecordSet ist the GNUnet data structure for a list of resource records
// in a GNSBlock. As part of GNUnet messages, the record set is padded so that
// the binary size of (records||padding) is the smallest power of two.
type RecordSet struct {
	Count   uint32            `order:"big"`  // number of resource records
	Records []*ResourceRecord `size:"Count"` // list of resource records
	Padding []byte            `size:"*"`     // padding
}

// NewRecordSet returns an empty resource record set.
func NewRecordSet() *RecordSet {
	return &RecordSet{
		Count:   0,
		Records: make([]*ResourceRecord, 0),
		Padding: make([]byte, 0),
	}
}

// AddRecord to append a resource record to the set.
func (rs *RecordSet) AddRecord(rec *ResourceRecord) {
	rs.Count++
	rs.Records = append(rs.Records, rec)
}

// SignedBlockData represents the signed and encrypted list of resource
// records stored in a GNSRecordSet
type SignedBlockData struct {
	Purpose *crypto.SignaturePurpose // Size and purpose of signature (8 bytes)
	Expire  util.AbsoluteTime        // Expiration time of the block.
	EncData []byte                   `size:"*"` // encrypted GNSRecordSet

	// transient data (not serialized)
	data []byte // decrypted GNSRecord set
}

// Block is the result of GNS lookups for a given label in a zone.
// An encrypted and signed container for GNS resource records that represents
// the "atomic" data structure associated with a GNS label in a given zone.
type Block struct {
	Signature  []byte `size:"64"` // Signature of the block.
	DerivedKey []byte `size:"32"` // Derived key used for signing
	Block      *SignedBlockData

	// transient data (not serialized)
	checked   bool // block integrity checked
	verified  bool // block signature verified (internal)
	decrypted bool // block data decrypted (internal)
}

// String returns the human-readable representation of a GNSBlock
func (b *Block) String() string {
	return fmt.Sprintf("GNSBlock{Verified=%v,Decrypted=%v,data=[%d]}",
		b.verified, b.decrypted, len(b.Block.EncData))
}

// Records returns the list of resource records in a block.
func (b *Block) Records() ([]*ResourceRecord, error) {
	// check if block is decrypted
	if !b.decrypted {
		return nil, ErrBlockNotDecrypted
	}
	// parse block data into record set
	rs := NewRecordSet()
	if err := data.Unmarshal(rs, b.Block.data); err != nil {
		return nil, err
	}
	return rs.Records, nil
}

// Verify the integrity of the block data from a signature.
func (b *Block) Verify(zoneKey *ed25519.PublicKey, label string) (err error) {
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
func (b *Block) Decrypt(zoneKey *ed25519.PublicKey, label string) (err error) {
	// decrypt payload
	b.Block.data, err = crypto.DecryptBlock(b.Block.EncData, zoneKey, label)
	b.decrypted = true
	return
}

// NewBlock instantiates an empty GNS block
func NewBlock() *Block {
	return &Block{
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

// ResourceRecord is the GNUnet-specific representation of resource
// records (not to be confused with DNS resource records).
type ResourceRecord struct {
	Expires util.AbsoluteTime // Expiration time for the record
	Size    uint32            `order:"big"` // Number of bytes in 'Data'
	Type    uint32            `order:"big"` // Type of the GNS/DNS record
	Flags   uint32            `order:"big"` // Flags for the record
	Data    []byte            `size:"Size"` // Record data
}

// String returns a human-readable representation of the message.
func (r *ResourceRecord) String() string {
	return fmt.Sprintf("GNSResourceRecord{type=%s,expire=%s,flags=%d,size=%d}",
		enums.GNS_TYPE[int(r.Type)], r.Expires, r.Flags, r.Size)
}

// LookupResultMsg is a response message for a GNS name lookup request
type LookupResultMsg struct {
	MsgSize uint16            `order:"big"`  // total size of message
	MsgType uint16            `order:"big"`  // GNS_LOOKUP_RESULT (501)
	ID      uint32            `order:"big"`  // Unique identifier for this request (for key collisions).
	Count   uint32            `order:"big"`  // The number of records contained in response
	Records []*ResourceRecord `size:"Count"` // GNS resource records
}

// NewGNSLookupResultMsg returns a new lookup result message
func NewGNSLookupResultMsg(id uint32) *LookupResultMsg {
	return &LookupResultMsg{
		MsgSize: 12, // Empty result (no records)
		MsgType: GNS_LOOKUP_RESULT,
		ID:      id,
		Count:   0,
		Records: make([]*ResourceRecord, 0),
	}
}

// AddRecord adds a GNS resource recordto the response message.
func (m *LookupResultMsg) AddRecord(rec *ResourceRecord) error {
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
func (m *LookupResultMsg) String() string {
	return fmt.Sprintf("GNSLookupResultMsg{Id=%d,Count=%d}", m.ID, m.Count)
}

// Header returns the message header in a separate instance.
func (m *LookupResultMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}
