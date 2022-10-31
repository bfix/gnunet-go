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
func newGenericNamestoreMsg(id int, size uint16, mtype enums.MsgType) GenericNamestoreMsg {
	return GenericNamestoreMsg{
		MsgHeader: MsgHeader{size, mtype},
		ID:        uint32(id),
	}
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_ZONE_ITERATION_START
//----------------------------------------------------------------------

// NamestoreZoneIterStartMsg starts a new iteration over all labels in a zones
type NamestoreZoneIterStartMsg struct {
	GenericNamestoreMsg

	ZoneKey *crypto.ZonePrivate `init:"Init"` // private zone key
}

// NewNamecacheCacheMsg creates a new default message.
func NewNamestoreZoneIterStartMsg(id int, zone *crypto.ZonePrivate) *NamestoreZoneIterStartMsg {
	// check for mandatory key
	if zone == nil {
		return nil
	}
	size := uint16(zone.KeySize() + 12)
	return &NamestoreZoneIterStartMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, size, enums.MSG_NAMESTORE_ZONE_ITERATION_START),
		ZoneKey:             zone,
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
func NewNamestoreZoneIterNextMsg(id int, limit int) *NamestoreZoneIterNextMsg {
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
func NewNamestoreZoneIterStopMsg(id int) *NamestoreZoneIterStopMsg {
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
	ZoneKey  *crypto.ZonePrivate `init:"Init"`    // private zone key
	Name     []byte              `size:"NameLen"` // name string
	Records  []byte              `size:"RdLen"`   // serialized record data

	// transient state
	recset *blocks.RecordSet
}

// NewNamestoreRecordResultMsg returns an initialize record message
func NewNamestoreRecordResultMsg(id int, zk *crypto.ZonePrivate, label string) *NamestoreRecordResultMsg {
	size := uint16(zk.KeySize()+4) + uint16(len(label)+16)
	return &NamestoreRecordResultMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, size, enums.MSG_NAMESTORE_RECORD_RESULT),
		Expire:              util.AbsoluteTimeNever(),
		ZoneKey:             zk,
		NameLen:             uint16(len(label)),
		Name:                []byte(label),
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
	m.Records = rs.Bytes()
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
	return fmt.Sprintf("NamestoreRecordResultMsg{id=%d,zone=%s,label='%s', %d records}",
		m.ID, m.ZoneKey.ID(), string(m.Name), m.RdCount)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_RECORD_STORE
//----------------------------------------------------------------------

// NamestoreRecordStoreMsg for storing records
type NamestoreRecordStoreMsg struct {
	GenericNamestoreMsg

	ZoneKey  *crypto.ZonePrivate `init:"Init"`    // private zone key
	NameLen  uint16              `order:"big"`    // length of name (label)
	RdLen    uint16              `order:"big"`    // length of record data
	RdCount  uint16              `order:"big"`    // number of records
	Reserved uint16              `order:"big"`    // reserved
	Name     []byte              `size:"NameLen"` // name (label)
	Records  []byte              `size:"RdLen"`   // record data

	// transient state
	recset *blocks.RecordSet
}

// NewNamestoreRecordStoreMsg creates an initialized message (without records)
func NewNamestoreRecordStoreMsg(id int, zk *crypto.ZonePrivate, label string) *NamestoreRecordStoreMsg {
	size := uint16(zk.KeySize()+4) + uint16(len(label)+8)
	return &NamestoreRecordStoreMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, size, enums.MSG_NAMESTORE_RECORD_STORE),
		ZoneKey:             zk,
		NameLen:             uint16(len(label)),
		Name:                []byte(label),
		RdLen:               0,
		RdCount:             0,
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreRecordStoreMsg) Init() error {
	if m.recset == nil {
		m.recset = new(blocks.RecordSet)
		return data.Unmarshal(m.recset, m.Records)
	}
	return nil
}

// AddRecords adds the record data to the message
func (m *NamestoreRecordStoreMsg) AddRecords(rs *blocks.RecordSet) {
	// make sure the record set is padded correctly
	rs.SetPadding()
	// copy recordset to message
	m.RdCount = uint16(rs.Count)
	m.Records = rs.Bytes()
	m.RdLen = uint16(len(m.Records))
	m.MsgSize += m.RdLen
	m.recset = rs
}

// GetRecords returns the record set contained in message
func (m *NamestoreRecordStoreMsg) GetRecords() blocks.RecordSet {
	return *m.recset
}

// String returns a human-readable representation of the message.
func (m *NamestoreRecordStoreMsg) String() string {
	return fmt.Sprintf("NamestoreRecordStoreMsg{id=%d,zone=%s,label='%s',%d records}",
		m.ID, m.ZoneKey.ID(), string(m.Name), m.RdCount)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_RECORD_STORE_RESP
//----------------------------------------------------------------------

// NamestoreRecordStoreRespMsg is a response to a record store message
type NamestoreRecordStoreRespMsg struct {
	GenericNamestoreMsg

	Status   int32  `order:"big"`   // result status
	ErrLen   uint16 `order:"big"`   // length of error message
	Reserved uint16 `order:"big"`   // alignment
	Error    []byte `size:"ErrLen"` // error message
}

// NewNamestoreRecordStoreRespMsg creates a new message
func NewNamestoreRecordStoreRespMsg(id int, rc enums.ResultCode, err string) *NamestoreRecordStoreRespMsg {
	msg := &NamestoreRecordStoreRespMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(id, 16, enums.MSG_NAMESTORE_RECORD_STORE_RESPONSE),
		Status:              int32(rc),
	}
	if rc != enums.RC_OK {
		msg.MsgSize += uint16(len(err))
		msg.Error = []byte(err)
	}
	return msg
}

// Init called after unmarshalling a message to setup internal state
func (m *NamestoreRecordStoreRespMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamestoreRecordStoreRespMsg) String() string {
	var msg string
	if m.Status != int32(enums.RC_OK) {
		msg = ",err=" + string(m.Error)
	}
	return fmt.Sprintf("NamestoreRecordStoreRespMsg{id=%d,rc=%d%s}", m.ID, m.Status, msg)
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
func NewNamestoreLabelLookupMsg(id int, zk *crypto.ZonePrivate, label string, isEdit bool) *NamestoreLabelLookupMsg {
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
func NewNamestoreLabelLookupRespMsg(id int, zk *crypto.ZonePrivate, label string) *NamestoreLabelLookupRespMsg {
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
	m.Records = rs.Bytes()
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
func NewNamestoreZoneToNameMsg(id int, key any) *NamestoreZoneToNameMsg {
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
func NewNamestoreZoneToNameRespMsg(id int, zk *crypto.ZonePrivate, label string, status enums.ResultCode) *NamestoreZoneToNameRespMsg {
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
	m.Records = rs.Bytes()
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
func NewNamestoreMonitorStartMsg(id int, zk *crypto.ZonePrivate, iter enums.ResultCode, filter int) *NamestoreMonitorStartMsg {
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
func NewNamestoreMonitorNextMsg(id int, limit uint64) *NamestoreMonitorNextMsg {
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
