// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2022 Bernd Fix  >Y<
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

package blocks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

// Error messages
var (
	ErrBlockNotDecrypted    = errors.New("GNS block not decrypted")
	ErrBlockInvalidSig      = errors.New("invalid signature key for GNS Block")
	ErrBlockTypeNotVerified = errors.New("can't verify block type")
	ErrBlockCantDecrypt     = errors.New("can't decrypt block type")
)

// GNSContext for key derivation
const GNSContext = "gns"

//----------------------------------------------------------------------
// Query key for GNS lookups
//----------------------------------------------------------------------

// GNSQuery specifies the context for a basic GNS name lookup of an (atomic)
// label in a given zone identified by its public key.
type GNSQuery struct {
	GenericQuery
	Zone    *crypto.ZoneKey // Public zone key
	Label   string          // Atomic label
	derived *crypto.ZoneKey // Derived zone key from (zone,label)
}

// Verify the integrity of the block data from a signature.
func (q *GNSQuery) Verify(b Block) (err error) {
	switch blk := b.(type) {
	case *GNSBlock:
		// Integrity check performed
		blk.checked = true

		// verify derived key
		dkey := blk.DerivedKeySig.ZoneKey
		var dkey2 *crypto.ZoneKey
		if dkey2, _, err = q.Zone.Derive(q.Label, GNSContext); err != nil {
			return
		}
		if !dkey.Equal(dkey2) {
			err = ErrBlockInvalidSig
			return
		}
		// verify signature
		var buf []byte
		if buf, err = data.Marshal(blk.Body); err != nil {
			return
		}
		blk.verified, err = blk.DerivedKeySig.Verify(buf)

	default:
		err = ErrBlockTypeNotVerified
	}
	return
}

// Decrypt block data with a key derived from zone key and label.
func (q *GNSQuery) Decrypt(b Block) (err error) {
	switch blk := b.(type) {
	case *GNSBlock:
		// decrypt GNS payload
		blk.data, err = q.Zone.Decrypt(blk.Body.Data, q.Label, blk.Body.Expire)
		blk.decrypted = true
		return

	default:
		err = ErrBlockCantDecrypt
	}
	return
}

// NewGNSQuery assembles a new Query object for the given zone and label.
func NewGNSQuery(zkey *crypto.ZoneKey, label string) *GNSQuery {
	// derive a public key from (pkey,label) and set the repository
	// key as the SHA512 hash of the binary key representation.
	// (key blinding)
	pd, _, err := zkey.Derive(label, GNSContext)
	if err != nil {
		logger.Printf(logger.ERROR, "[NewGNSQuery] failed: %s", err.Error())
		return nil
	}
	gq := crypto.Hash(pd.Bytes())
	return &GNSQuery{
		GenericQuery: *NewGenericQuery(gq, enums.BLOCK_TYPE_GNS_NAMERECORD, 0),
		Zone:         zkey,
		Label:        label,
		derived:      pd,
	}
}

//----------------------------------------------------------------------
// GNS blocks
//----------------------------------------------------------------------

// SignedGNSBlockData represents the signed content of a GNS block
type SignedGNSBlockData struct {
	Purpose *crypto.SignaturePurpose ``         // Size and purpose of signature (8 bytes)
	Expire  util.AbsoluteTime        ``         // Expiration time of the block.
	Data    []byte                   `size:"*"` // Block data content
}

// GNSBlock is the result of GNS lookups for a given label in a zone.
// An encrypted and signed container for GNS resource records that represents
// the "atomic" data structure associated with a GNS label in a given zone.
type GNSBlock struct {

	// persistent
	DerivedKeySig *crypto.ZoneSignature // Derived key used for signing
	Body          *SignedGNSBlockData

	// transient data (not serialized)
	checked   bool   // block integrity checked
	verified  bool   // block signature verified (internal)
	decrypted bool   // block decrypted (internal)
	data      []byte // decrypted data
}

// Payload returns the decrypted block data (or nil)
func (b *GNSBlock) Payload() []byte {
	return util.Clone(b.data)
}

// Bytes return the binary representation of block
func (b *GNSBlock) Bytes() []byte {
	buf, _ := data.Marshal(b)
	return buf
}

// RRBLOCK returns the block according to spec
func (b *GNSBlock) RRBLOCK() []byte {
	// compute size of output
	size := uint32(16 + b.DerivedKeySig.SigSize() + b.DerivedKeySig.KeySize() + uint(len(b.Body.Data)))
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, size)
	_ = binary.Write(buf, binary.BigEndian, b.DerivedKeySig.Type)
	buf.Write(b.DerivedKeySig.KeyData)
	buf.Write(b.DerivedKeySig.Bytes())
	_ = binary.Write(buf, binary.BigEndian, b.Body.Expire.Val)
	buf.Write(b.Body.Data)
	return buf.Bytes()
}

// Expire returns the expiration date of the block.
func (b *GNSBlock) Expire() util.AbsoluteTime {
	return b.Body.Expire
}

// Type returns the requested block type
func (b *GNSBlock) Type() enums.BlockType {
	return enums.BLOCK_TYPE_GNS_NAMERECORD
}

// String returns the human-readable representation of a GNSBlock
func (b *GNSBlock) String() string {
	return fmt.Sprintf("GNSBlock{Verified=%v,Decrypted=%v,data=[%d]}",
		b.verified, b.decrypted, len(b.Body.Data))
}

// NewGNSBlock instantiates an empty GNS block
func NewGNSBlock() Block {
	return &GNSBlock{
		DerivedKeySig: nil,
		Body: &SignedGNSBlockData{
			Purpose: &crypto.SignaturePurpose{
				Size:    16,
				Purpose: enums.SIG_GNS_RECORD_SIGN,
			},
			Expire: util.AbsoluteTimeNever(),
			Data:   nil,
		},
		checked:   false,
		verified:  false,
		decrypted: false,
		data:      nil,
	}
}

// Prepare a block to be of given type and expiration.
// Not required for GNS blocks
func (b *GNSBlock) Prepare(_ enums.BlockType, ts util.AbsoluteTime) {
	b.Body.Expire = ts
}

// SetData sets the data for the GNS block
func (b *GNSBlock) SetData(data []byte) {
	b.Body.Data = data
	b.Body.Purpose.Size = uint32(len(data) + 16)
}

// Sign the block with a derived private key
func (b *GNSBlock) Sign(sk *crypto.ZonePrivate) error {
	// get signed data
	buf, err := data.Marshal(b.Body)
	if err == nil {
		// generate signature
		b.DerivedKeySig, err = sk.Sign(buf)
	}
	return err
}

// Verify the integrity of the block data from a signature.
// Only the cryptographic signature is verified; the formal correctness of
// the association between the block and a GNS label in a GNS zone can't
// be verified. This is only possible in Query.Verify().
func (b *GNSBlock) Verify() (ok bool, err error) {
	// verify signature
	var buf []byte
	if buf, err = data.Marshal(b.Body); err != nil {
		return
	}
	return b.DerivedKeySig.Verify(buf)
}

//----------------------------------------------------------------------
// Resource record
//----------------------------------------------------------------------

// RecordSet is the GNUnet data structure for a list of resource records
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
		Padding: nil,
	}
}

// NewRecordSetFromRDATA converts RDATA (see GNS spec) to rcord set
func NewRecordSetFromRDATA(count uint32, rdata []byte) (rs *RecordSet, err error) {
	rs = new(RecordSet)

	// do we know the number of records?
	if count == 0 {
		// no: try to compute from rdata
		var size uint16
		for pos := 8; pos < len(rdata); {
			if err = binary.Read(bytes.NewReader(rdata[pos:pos+2]), binary.BigEndian, &size); err != nil {
				err = nil
				break
			}
			count++
			pos += int(size) + 16
		}
	}
	if count == 0 {
		return
	}
	// generate intermediate buffer
	wrt := new(bytes.Buffer)
	_ = binary.Write(wrt, binary.BigEndian, count)
	_, _ = wrt.Write(rdata)
	buf := wrt.Bytes()
	// unmarshal record set
	err = data.Unmarshal(rs, buf)
	return
}

// AddRecord to append a resource record to the set.
func (rs *RecordSet) AddRecord(rec *ResourceRecord) {
	rs.Count++
	rs.Records = append(rs.Records, rec)
}

// SetPadding (re-)calculates and allocates the padding.
func (rs *RecordSet) SetPadding() {
	// do not add padding to single delegation record
	typ := rs.Records[0].RType
	if len(rs.Records) == 1 && (typ == enums.GNS_TYPE_PKEY || typ == enums.GNS_TYPE_EDKEY) {
		return
	}
	// compute padding size
	size := 0
	for _, rr := range rs.Records {
		size += int(rr.Size) + 16
	}
	n := 1
	for n < size {
		n <<= 1
	}
	rs.Padding = make([]byte, n-size)
}

// Expire returns the earliest expiration timestamp for the records.
func (rs *RecordSet) Expire() util.AbsoluteTime {
	var expires util.AbsoluteTime
	for i, rr := range rs.Records {
		if i == 0 {
			expires = rr.Expire
		} else if rr.Expire.Compare(expires) < 0 {
			expires = rr.Expire
		}
	}
	return expires
}

// RDATA returns the binary representation of the record set as specified
// in the GNS draft.
func (rs *RecordSet) RDATA() []byte {
	// make sure padding exists
	if rs.Padding == nil {
		rs.SetPadding()
	}
	// unmarshal record set
	buf, err := data.Marshal(rs)
	if err != nil {
		return nil
	}
	return buf[4:]
}

//----------------------------------------------------------------------
// Resource record
//----------------------------------------------------------------------

// ResourceRecord is the GNUnet-specific representation of resource
// records (not to be confused with DNS resource records).
type ResourceRecord struct {
	Expire util.AbsoluteTime ``            // Expiration time for the record
	Size   uint16            `order:"big"` // Number of bytes in 'Data'
	Flags  enums.GNSFlag     `order:"big"` // Flags
	RType  enums.GNSType     `order:"big"` // Type of the GNS/DNS record
	Data   []byte            `size:"Size"` // Record data
}

// String returns a human-readable representation of the message.
func (r *ResourceRecord) String() string {
	return fmt.Sprintf("GNSResourceRecord{type=%s,expire=%s,flags=%d,size=%d}",
		r.RType.String(), r.Expire, r.Flags, r.Size)
}
