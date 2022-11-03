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

package message

import (
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/service/dht/blocks"
	"gnunet/util"

	"github.com/bfix/gospel/data"
)

//======================================================================
// NameStore service messages
//======================================================================

// GenericNamestoreMsg is the common header for Namestore messages
type GenericNamestoreMsg struct {
	MsgHeader
	ID uint32 `order:"big"` // unique reference ID
}

// return initialized common message header
func newGenericNamestoreMsg(id uint32, size uint16, mtype enums.MsgType) GenericNamestoreMsg {
	return GenericNamestoreMsg{
		MsgHeader: MsgHeader{size, mtype},
		ID:        id,
	}
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_ZONE_ITERATION_START
//----------------------------------------------------------------------

// NamestoreZoneIterStartMsg starts a new iteration over all labels in a zones
type NamestoreZoneIterStartMsg struct {
	GenericNamestoreMsg

	Filter   uint16              `order:"big"` // filter settings
	Reserved uint16              `order:"big"` // Reserved
	KeyLen   uint32              `order:"big"` // length of private key
	ZoneKey  *crypto.ZonePrivate `init:"Init"` // private zone key
}

// NewNamecacheCacheMsg creates a new default message.
func NewNamestoreZoneIterStartMsg(id uint32, filter int, zone *crypto.ZonePrivate) *NamestoreZoneIterStartMsg {
	var size uint16 = 16
	var kl uint32 = 0
	if zone != nil {
		kl = uint32(zone.KeySize()) + 4
		size += uint16(kl)
	}
	return &NamestoreZoneIterStartMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, size, enums.MSG_NAMESTORE_ZONE_ITERATION_START),
		Filter:              uint16(filter),
		ZoneKey:             zone,
		KeyLen:              kl,
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreZoneIterStartMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamestoreZoneIterStartMsg) String() string {
	return fmt.Sprintf("NamestoreZoneIterStartMsg{id=%d,zone=%s}", m.ID, m.ZoneKey.ID())
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_ZONE_ITERATION_NEXT
//----------------------------------------------------------------------

// NamestoreZoneIterNextMsg returns the next labels
type NamestoreZoneIterNextMsg struct {
	GenericNamestoreMsg

	Limit uint64 `order:"big"` // max. number of records in one go
}

// NewNamestoreZoneIterNextMsg creates a message with given limit
func NewNamestoreZoneIterNextMsg(id uint32, limit int) *NamestoreZoneIterNextMsg {
	return &NamestoreZoneIterNextMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, 16, enums.MSG_NAMESTORE_ZONE_ITERATION_NEXT),
		Limit:               uint64(limit),
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreZoneIterNextMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamestoreZoneIterNextMsg) String() string {
	return fmt.Sprintf("NamestoreZoneIterNextMsg{id=%d,limit=%d}", m.ID, m.Limit)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_ZONE_ITERATION_STOP
//----------------------------------------------------------------------

// NamestoreZoneIterStopMsg stops a running iterator
type NamestoreZoneIterStopMsg struct {
	GenericNamestoreMsg
}

// NewNamestoreZoneIterNextMsg creates a stop message
func NewNamestoreZoneIterStopMsg(id uint32) *NamestoreZoneIterStopMsg {
	return &NamestoreZoneIterStopMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, 8, enums.MSG_NAMESTORE_ZONE_ITERATION_STOP),
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreZoneIterStopMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamestoreZoneIterStopMsg) String() string {
	return fmt.Sprintf("NamestoreZoneIterStopMsg{id=%d}", m.ID)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_ZONE_ITERATION_END
//----------------------------------------------------------------------

// NamestoreZoneIterEndMsg stops a running iterator
type NamestoreZoneIterEndMsg struct {
	GenericNamestoreMsg
}

// NewNamestoreZoneIterEndMsg creates a stop message
func NewNamestoreZoneIterEndMsg(id uint32) *NamestoreZoneIterEndMsg {
	return &NamestoreZoneIterEndMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, 8, enums.MSG_NAMESTORE_ZONE_ITERATION_END),
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreZoneIterEndMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamestoreZoneIterEndMsg) String() string {
	return fmt.Sprintf("NamestoreZoneIterEndMsg{id=%d}", m.ID)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_RECORD_RESULT
//----------------------------------------------------------------------

// NamestoreRecordResultMsg returns the records for a label (name)
type NamestoreRecordResultMsg struct {
	GenericNamestoreMsg

	Expire   util.AbsoluteTime   ``               // expiration date
	NameLen  uint16              `order:"big"`    // length of name
	RdLen    uint16              `order:"big"`    // size of record data
	RdCount  uint16              `order:"big"`    // number of records
	Reserved uint16              `order:"big"`    // alignment
	KeyLen   uint32              `order:"big"`    // length of key
	ZoneKey  *crypto.ZonePrivate `init:"Init"`    // private zone key
	Name     []byte              `size:"NameLen"` // name string
	Records  []byte              `size:"RdLen"`   // serialized record data

	// transient state
	recset *blocks.RecordSet
}

// NewNamestoreRecordResultMsg returns an initialize record message
func NewNamestoreRecordResultMsg(id uint32, zk *crypto.ZonePrivate, label string) *NamestoreRecordResultMsg {
	var kl uint32
	if zk != nil {
		kl = uint32(zk.KeySize()) + 4
	}
	nl := uint16(len(label) + 1)
	size := uint16(kl) + nl + 28
	return &NamestoreRecordResultMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, size, enums.MSG_NAMESTORE_RECORD_RESULT),
		Expire:              util.AbsoluteTimeNever(),
		KeyLen:              kl,
		ZoneKey:             zk,
		NameLen:             nl,
		Name:                util.WriteCString(label),
		RdLen:               0,
		RdCount:             0,
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreRecordResultMsg) Init() error {
	if m.recset == nil {
		m.recset = new(blocks.RecordSet)
		return data.Unmarshal(m.recset, m.Records)
	}
	return nil
}

// AddRecords adds the record data to the message
func (m *NamestoreRecordResultMsg) AddRecords(rs *blocks.RecordSet) {
	// make sure the record set is padded correctly
	rs.SetPadding()
	// copy recordset to message
	m.RdCount = uint16(rs.Count)
	m.Records = rs.RDATA()
	m.RdLen = uint16(len(m.Records))
	m.MsgSize += m.RdLen
	m.recset = rs
}

// GetRecords returns the record set contained in message
func (m *NamestoreRecordResultMsg) GetRecords() blocks.RecordSet {
	return *m.recset
}

// String returns a human-readable representation of the message.
func (m *NamestoreRecordResultMsg) String() string {
	zone, label := "", ""
	if !m.ZoneKey.IsNull() {
		zone = fmt.Sprintf(",zone=%s", m.ZoneKey.ID())
	}
	if m.NameLen > 0 {
		lbl, _ := util.ReadCString(m.Name, 0)
		label = fmt.Sprintf(",label='%s'", lbl)
	}
	return fmt.Sprintf("NamestoreRecordResultMsg{id=%d%s%s,%d records}",
		m.ID, zone, label, m.RdCount)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_RECORD_STORE
//----------------------------------------------------------------------

// NamestoreRecordSet for a label
type NamestoreRecordSet struct {
	NameLen  uint16 `order:"big"`    // Length of label
	RdLen    uint16 `order:"big"`    // length of record data
	RdCount  uint16 `order:"big"`    // number of records
	Reserved uint16 `order:"big"`    // reserved
	Name     []byte `size:"NameLen"` // label name
	RecData  []byte `size:"RdLen"`   // record data
}

// NewNamestoreRecordSet for label and resource records.
func NewNamestoreRecordSet(label string, rr *blocks.RecordSet) (rs *NamestoreRecordSet, size uint16) {
	// make sure the record set is padded correctly
	rr.SetPadding()

	// copy recordset to message
	rs = new(NamestoreRecordSet)
	rs.NameLen = uint16(len(label) + 1)
	rs.Name = util.WriteCString(label)
	rs.RdCount = uint16(rr.Count)
	rs.RecData = rr.RDATA()
	rs.RdLen = uint16(len(rs.RecData))
	size = rs.RdLen + rs.NameLen + 8
	return
}

//----------------------------------------------------------------------

// NamestoreRecordStoreMsg for storing records (multiple labels at a
// time possible)
type NamestoreRecordStoreMsg struct {
	GenericNamestoreMsg

	Count   uint16                `order:"big"`  // number of RecordSets
	KeyLen  uint32                `order:"big"`  // length of zone key
	ZoneKey *crypto.ZonePrivate   `init:"Init"`  // private zone key
	RSets   []*NamestoreRecordSet `size:"Count"` // list of label record sets
}

// NewNamestoreRecordStoreMsg creates an initialized message (without records)
func NewNamestoreRecordStoreMsg(id uint32, zk *crypto.ZonePrivate) *NamestoreRecordStoreMsg {
	var kl uint32
	if zk != nil {
		kl = uint32(zk.KeySize() + 4)
	}
	size := uint16(kl) + 14
	return &NamestoreRecordStoreMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, size, enums.MSG_NAMESTORE_RECORD_STORE),
		ZoneKey:             zk,
		Count:               0,
		KeyLen:              kl,
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreRecordStoreMsg) Init() error {
	return nil
}

// AddRecords adds the record data to the message
func (m *NamestoreRecordStoreMsg) AddRecordSet(label string, rr *blocks.RecordSet) {
	rs, size := NewNamestoreRecordSet(label, rr)
	m.RSets = append(m.RSets, rs)
	m.MsgSize += size
}

// String returns a human-readable representation of the message.
func (m *NamestoreRecordStoreMsg) String() string {
	return fmt.Sprintf("NamestoreRecordStoreMsg{id=%d,zone=%s,%d record sets}",
		m.ID, m.ZoneKey.ID(), m.Count)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_RECORD_STORE_RESP
//----------------------------------------------------------------------

// NamestoreRecordStoreRespMsg is a response to a record store message
type NamestoreRecordStoreRespMsg struct {
	GenericNamestoreMsg

	Status uint32 `order:"big"` // result status
}

// NewNamestoreRecordStoreRespMsg creates a new message
func NewNamestoreRecordStoreRespMsg(id uint32, rc uint32) *NamestoreRecordStoreRespMsg {
	return &NamestoreRecordStoreRespMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, 12, enums.MSG_NAMESTORE_RECORD_STORE_RESPONSE),
		Status:              rc,
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreRecordStoreRespMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamestoreRecordStoreRespMsg) String() string {
	return fmt.Sprintf("NamestoreRecordStoreRespMsg{id=%d,rc=%d}", m.ID, m.Status)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_RECORD_LOOKUP
//----------------------------------------------------------------------

type NamestoreLabelLookupMsg struct {
	GenericNamestoreMsg

	LblLen  uint32              `order:"big"`   // length of label
	IsEdit  uint32              `order:"big"`   // lookup corresponds to edit request
	ZoneKey *crypto.ZonePrivate `init:"Init"`   // private zone key
	Label   []byte              `size:"LblLen"` // label string
}

// NewNamestoreLabelLookupMsg creates a new message
func NewNamestoreLabelLookupMsg(id uint32, zk *crypto.ZonePrivate, label string, isEdit bool) *NamestoreLabelLookupMsg {
	var flag uint32
	if isEdit {
		flag = 1
	}
	size := uint16(zk.KeySize()+4) + uint16(len(label)) + 16
	return &NamestoreLabelLookupMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, size, enums.MSG_NAMESTORE_RECORD_LOOKUP),
		IsEdit:              flag,
		ZoneKey:             zk,
		LblLen:              uint32(len(label)),
		Label:               []byte(label),
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreLabelLookupMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamestoreLabelLookupMsg) String() string {
	return fmt.Sprintf("NamestoreLabelLookupMsg{id=%d,zk=%s,label=%s,edit=%v}",
		m.ID, m.ZoneKey.ID(), string(m.Label), m.IsEdit != 0)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_RECORD_LOOKUP_RESPONSE
//----------------------------------------------------------------------

// NamestoreLabelLookupRespMsg is a lookup response message
type NamestoreLabelLookupRespMsg struct {
	GenericNamestoreMsg

	LblLen  uint16              `order:"big"`   // Length of label
	RdLen   uint16              `order:"big"`   // size of record data
	RdCount uint16              `order:"big"`   // number of records
	Found   int16               `order:"big"`   // label found?
	ZoneKey *crypto.ZonePrivate `init:"Init"`   // private zone key
	Label   []byte              `size:"LblLen"` // label string
	Records []byte              `size:"RdLen"`  // serialized record data

	// transient state
	recset *blocks.RecordSet
}

// NewNamestoreLabelLookupRespMsg creates a new message
func NewNamestoreLabelLookupRespMsg(id uint32, zk *crypto.ZonePrivate, label string) *NamestoreLabelLookupRespMsg {
	size := uint16(zk.KeySize()+4) + uint16(len(label)) + 16
	msg := &NamestoreLabelLookupRespMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, size, enums.MSG_NAMESTORE_RECORD_LOOKUP_RESPONSE),
		ZoneKey:             zk,
		LblLen:              uint16(len(label)),
		Label:               []byte(label),
		Records:             nil,
	}
	return msg
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreLabelLookupRespMsg) Init() error {
	if m.recset == nil {
		m.recset = new(blocks.RecordSet)
		return data.Unmarshal(m.recset, m.Records)
	}
	return nil
}

// AddRecords adds the record data to the message
func (m *NamestoreLabelLookupRespMsg) AddRecords(rs *blocks.RecordSet) {
	// make sure the record set is padded correctly
	rs.SetPadding()
	// copy recordset to message
	m.RdCount = uint16(rs.Count)
	m.Records = rs.RDATA()
	m.RdLen = uint16(len(m.Records))
	m.MsgSize += m.RdLen
	m.recset = rs
}

// GetRecords returns the record set contained in message
func (m *NamestoreLabelLookupRespMsg) GetRecords() blocks.RecordSet {
	return *m.recset
}

// String returns a human-readable representation of the message.
func (m *NamestoreLabelLookupRespMsg) String() string {
	return fmt.Sprintf("NamestoreLabelLookupRespMsg{id=%d,zone=%s,label='%s',%d records}",
		m.ID, m.ZoneKey.ID(), string(m.Label), m.RdCount)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_ZONE_TO_NAME
//----------------------------------------------------------------------

// NamestoreZoneToNameMsg resolves the name for a given key
type NamestoreZoneToNameMsg struct {
	GenericNamestoreMsg

	ZoneKey    *crypto.ZonePrivate `init:"Init"` // private zone key
	ZonePublic *crypto.ZoneKey     `init:"Init"` // public zone key
}

// NewNamestoreZoneIterNextMsg creates a new message
func NewNamestoreZoneToNameMsg(id uint32, key any) *NamestoreZoneToNameMsg {
	// create message
	msg := &NamestoreZoneToNameMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, 8, enums.MSG_NAMESTORE_ZONE_TO_NAME),
	}
	// set either public or private key
	switch x := key.(type) {
	case *crypto.ZonePrivate:
		msg.ZoneKey = x
		msg.ZonePublic, _ = crypto.NullZoneKey(x.Type)
	case *crypto.ZoneKey:
		msg.ZonePublic = x
		msg.ZoneKey, _ = crypto.NullZonePrivate(x.Type)
	}
	return msg
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreZoneToNameMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamestoreZoneToNameMsg) String() string {
	var key string
	if m.ZoneKey.IsNull() {
		key = m.ZonePublic.ID()
	} else {
		key = m.ZoneKey.Public().ID()
	}
	return fmt.Sprintf("NamestoreZoneToNameMsg{id=%d,zk=%s}", m.ID, key)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_ZONE_TO_NAME_RESPONSE
//----------------------------------------------------------------------

// NamestoreZoneToNameRespMsg is a response to NamestoreZoneToNameMsg
type NamestoreZoneToNameRespMsg struct {
	GenericNamestoreMsg

	NameLen uint16              `order:"big"`    // length of name
	RdLen   uint16              `order:"big"`    // size of record data
	RdCount uint16              `order:"big"`    // number of records
	Status  int16               `order:"big"`    // result status
	ZoneKey *crypto.ZonePrivate `init:"Init"`    // private zone key
	Name    []byte              `size:"NameLen"` // name string
	Records []byte              `size:"RdLen"`   // serialized record data

	// transient state
	recset *blocks.RecordSet
}

// NewNamestoreNamestoreZoneToNameRespMsgMsg creates a new message
func NewNamestoreZoneToNameRespMsg(id uint32, zk *crypto.ZonePrivate, label string, status enums.ResultCode) *NamestoreZoneToNameRespMsg {
	return &NamestoreZoneToNameRespMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, 8, enums.MSG_NAMESTORE_ZONE_TO_NAME_RESPONSE),
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreZoneToNameRespMsg) Init() error {
	if m.recset == nil {
		m.recset = new(blocks.RecordSet)
		return data.Unmarshal(m.recset, m.Records)
	}
	return nil
}

// AddRecords adds the record data to the message
func (m *NamestoreZoneToNameRespMsg) AddRecords(rs *blocks.RecordSet) {
	// make sure the record set is padded correctly
	rs.SetPadding()
	// copy recordset to message
	m.RdCount = uint16(rs.Count)
	m.Records = rs.RDATA()
	m.RdLen = uint16(len(m.Records))
	m.MsgSize += m.RdLen
	m.recset = rs
}

// GetRecords returns the record set contained in message
func (m *NamestoreZoneToNameRespMsg) GetRecords() blocks.RecordSet {
	return *m.recset
}

// String returns a human-readable representation of the message.
func (m *NamestoreZoneToNameRespMsg) String() string {
	return fmt.Sprintf("NamestoreZoneToNameRespMsg{id=%d,zone=%s,label='%s',%d records}",
		m.ID, m.ZoneKey.ID(), string(m.Name), m.RdCount)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_MONITOR_START
//----------------------------------------------------------------------

// NamestoreMonitorStartMsg starts a monitor session
type NamestoreMonitorStartMsg struct {
	GenericNamestoreMsg

	Iterate  enums.ResultCode    `order:"big"` // iterate over all records
	Filter   uint16              `order:"big"` // filter flags
	Reserved uint16              `order:"big"` // alignment
	ZoneKey  *crypto.ZonePrivate `init:"Init"` // private zone key
}

// NewNamestoreMonitorStartMsg creates a new message
func NewNamestoreMonitorStartMsg(id uint32, zk *crypto.ZonePrivate, iter enums.ResultCode, filter int) *NamestoreMonitorStartMsg {
	size := uint16(zk.KeySize()+4) + 16
	return &NamestoreMonitorStartMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, size, enums.MSG_NAMESTORE_MONITOR_START),
		Iterate:             iter,
		Filter:              uint16(filter),
		ZoneKey:             zk,
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreMonitorStartMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamestoreMonitorStartMsg) String() string {
	return fmt.Sprintf("NamestoreMonitorStartMsg{id=%d,zone=%s,iter=%v,filter=%d}",
		m.ID, m.ZoneKey.ID(), m.Iterate == enums.RC_OK, m.Filter)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_RECORD_STORE_RESP
//----------------------------------------------------------------------

// NamestoreMonitorNextMsg to retrieve next set of results
type NamestoreMonitorNextMsg struct {
	GenericNamestoreMsg

	Reserved uint32 `order:"big"` // alignment =0
	Limit    uint64 `order:"big"` // max. number of records in one go
}

// NewNamestoreMonitorNextMsg creates a new message
func NewNamestoreMonitorNextMsg(id uint32, limit uint64) *NamestoreMonitorNextMsg {
	return &NamestoreMonitorNextMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, 20, enums.MSG_NAMESTORE_MONITOR_NEXT),
		Limit:               limit,
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreMonitorNextMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamestoreMonitorNextMsg) String() string {
	return fmt.Sprintf("NamestoreMonitorNextMsg{id=%d,limit=%d}", m.ID, m.Limit)
}
