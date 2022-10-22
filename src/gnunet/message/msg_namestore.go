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
func newGenericNamestoreMsg(size uint16, mtype enums.MsgType) GenericNamestoreMsg {
	return GenericNamestoreMsg{
		MsgHeader: MsgHeader{size, mtype},
		ID:        uint32(util.NextID()),
	}
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_ZONE_ITERATION_START
//----------------------------------------------------------------------

// NamestoreZoneIterStartMsg starts a new iteration over all zones
type NamestoreZoneIterStartMsg struct {
	GenericNamestoreMsg

	ZoneKey *crypto.ZonePrivate // private zone key
}

// NewNamecacheCacheMsg creates a new default message.
func NewNamestoreZoneIterStartMsg(zone *crypto.ZonePrivate) *NamestoreZoneIterStartMsg {
	return &NamestoreZoneIterStartMsg{
		GenericNamestoreMsg: newGenericNamestoreMsg(100, enums.MSG_NAMESTORE_ZONE_ITERATION_START),
		ZoneKey:             zone,
	}
}

// String returns a human-readable representation of the message.
func (m *NamestoreZoneIterStartMsg) String() string {
	return fmt.Sprintf("NamestoreZoneIterStartMsg{id=%d,zone=%s}", m.ID, m.ZoneKey.ID())
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_ZONE_ITERATION_NEXT
//----------------------------------------------------------------------

type NamestoreZoneIterNextMsg struct {
	GenericNamestoreMsg

	Limit uint64 `order:"big"` // max. number of records in one go
}

func NewNamestoreZoneIterNextMsg() *NamestoreZoneIterNextMsg {
	return &NamestoreZoneIterNextMsg{}
}

// String returns a human-readable representation of the message.
func (m *NamestoreZoneIterNextMsg) String() string {
	return fmt.Sprintf("NamestoreZoneIterNextMsg{id=%d,limit=%d}", m.ID, m.Limit)
}

//----------------------------------------------------------------------
// MSG_NAMESTORE_ZONE_ITERATION_STOP
//----------------------------------------------------------------------

type NamestoreZoneIterStopMsg struct {
	GenericNamestoreMsg
}

//----------------------------------------------------------------------
//----------------------------------------------------------------------

type NamestoreRecordStoreMsg struct {
	GenericNamestoreMsg

	ZoneKey *crypto.ZonePrivate // private zone key
	Records *blocks.RecordSet   // list of records
}

type NamestoreRecordStoreRespMsg struct {
	GenericNamestoreMsg

	Status   int32  `order:"big"`   // result status
	ErrLen   uint16 `order:"big"`   // length of error message
	Reserved uint16 `order:"big"`   // alignment
	Error    []byte `size:"ErrLen"` // error message
}

type NamestoreLabelLookupMsg struct {
	GenericNamestoreMsg

	LblLen  uint32              `order:"big"` // length of label
	IsEdit  uint32              `order:"big"` // lookup corresponds to edit request
	ZoneKey *crypto.ZonePrivate // private zone key
	Label   []byte              `size:"LblLen"` // label string
}

type NamestoreLabelLookupRespMsg struct {
	GenericNamestoreMsg

	LblLen  uint16              `order:"big"` // Length of label
	RdLen   uint16              `order:"big"` // size of record data
	RdCount uint16              `order:"big"` // number of records
	Found   int16               `order:"big"` // label found?
	ZoneKey *crypto.ZonePrivate // private zone key
	Label   []byte              `size:"LblLen"` // label string
	Records []byte              `size:"RdLen"`  // serialized record data
}

type NamestoreZoneToNameMsg struct {
	GenericNamestoreMsg

	ZoneKey    *crypto.ZonePrivate // private zone key
	ZonePublic *crypto.ZoneKey     // public zone key
}

type NamestoreZoneToNameRespMsg struct {
	GenericNamestoreMsg

	NameLen uint16              `order:"big"` // length of name
	RdLen   uint16              `order:"big"` // size of record data
	RdCount uint16              `order:"big"` // number of records
	Status  int16               `order:"big"` // result status
	ZoneKey *crypto.ZonePrivate // private zone key
	Name    []byte              `size:"NameLen"` // name string
	Records []byte              `size:"RdLen"`   // serialized record data
}

type NamestoreRecordResultMsg struct {
	GenericNamestoreMsg

	Expire   util.AbsoluteTime   ``            // expiration date
	NameLen  uint16              `order:"big"` // length of name
	RdLen    uint16              `order:"big"` // size of record data
	RdCount  uint16              `order:"big"` // number of records
	Reserved uint16              `order:"big"` // alignment
	ZoneKey  *crypto.ZonePrivate // private zone key
	Name     []byte              `size:"NameLen"` // name string
	Records  []byte              `size:"RdLen"`   // serialized record data
}

type NamestoreTxControlMsg struct {
	GenericNamestoreMsg

	Control  uint16 `order:"big"` // type of control message
	Reserved uint16 `order:"big"` // alignment
}

type NamestoreTxControlResultMsg struct {
	GenericNamestoreMsg

	Control uint16 `order:"big"` // type of control message
	Status  uint16 `order:"big"` // result status
	Error   []byte `size:"*"`    // error message (on status != OK)
}

type NamestoreZoneMonStartMsg struct {
	GenericNamestoreMsg

	Iterate  uint32              `order:"big"` // iterate over all records
	Filter   uint16              `order:"big"` // filter flags
	Reserved uint16              `order:"big"` // alignment
	ZoneKey  *crypto.ZonePrivate // private zone key
}

type NamestoreZoneMonNextMsg struct {
	GenericNamestoreMsg

	Reserved uint32 `order:"big"` // alignment =0
	Limit    uint64 `order:"big"` // max. number of records in one go
}
