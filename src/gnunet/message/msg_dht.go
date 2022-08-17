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
	"gnunet/util"
)

//----------------------------------------------------------------------
// DHT_CLIENT_PUT
//----------------------------------------------------------------------

// DHTClientPutMsg is the message for putting values into the DHT
type DHTClientPutMsg struct {
	MsgHeader
	BType     enums.BlockType   `order:"big"` // The type of the data (BLOCK_TYPE_???)
	Options   uint32            `order:"big"` // Message options (DHT_RO_???)
	ReplLevel uint32            `order:"big"` // Replication level for this message
	Expire    util.AbsoluteTime // Expiration time
	Key       *crypto.HashCode  // The key to be used
	Data      []byte            `size:"*"` // Block data
}

// NewDHTClientPutMsg creates a new default DHTClientPutMsg object.
func NewDHTClientPutMsg(key *crypto.HashCode, btype enums.BlockType, data []byte) *DHTClientPutMsg {
	if key == nil {
		key = new(crypto.HashCode)
	}
	var size uint16 = 88
	if data != nil {
		size += uint16(len(data))
	}
	return &DHTClientPutMsg{
		MsgHeader: MsgHeader{size, enums.MSG_DHT_CLIENT_PUT},
		BType:     btype,
		Options:   uint32(enums.DHT_RO_NONE),
		ReplLevel: 1,
		Expire:    util.AbsoluteTimeNever(),
		Key:       key,
		Data:      data,
	}
}

// String returns a human-readable representation of the message.
func (m *DHTClientPutMsg) String() string {
	return fmt.Sprintf("DHTClientPutMsg{Type=%s,Expire=%s,Options=%d,Repl=%d,Key=%s}",
		m.BType, m.Expire, m.Options, m.ReplLevel, m.Key)
}

//----------------------------------------------------------------------
// DHT_CLIENT_GET
//----------------------------------------------------------------------

// DHTClientGetMsg is the message for getting values from the DHT
type DHTClientGetMsg struct {
	MsgHeader
	Options   uint32           `order:"big"` // Message options (DHT_RO_???)
	ReplLevel uint32           `order:"big"` // Replication level for this message
	BType     enums.BlockType  `order:"big"` // The type for the data for the GET request (BLOCK_TYPE_???)
	Key       *crypto.HashCode // The key to search for
	ID        uint64           `order:"big"` // Unique ID identifying this request
	XQuery    []byte           `size:"*"`    // Optional xquery
}

// NewDHTClientGetMsg creates a new default DHTClientGetMsg object.
func NewDHTClientGetMsg(key *crypto.HashCode) *DHTClientGetMsg {
	if key == nil {
		key = new(crypto.HashCode)
	}
	return &DHTClientGetMsg{
		MsgHeader: MsgHeader{88, enums.MSG_DHT_CLIENT_GET},
		Options:   uint32(enums.DHT_RO_NONE),
		ReplLevel: 1,
		BType:     enums.BLOCK_TYPE_ANY,
		Key:       key,
		ID:        0,
		XQuery:    nil,
	}
}

// SetXQuery sets a (new) XQuery in this message and return previous XQuery.
func (m *DHTClientGetMsg) SetXQuery(xq []byte) []byte {
	prev := m.XQuery
	m.MsgSize -= uint16(len(prev))
	m.XQuery = util.Clone(xq)
	m.MsgSize += uint16(len(xq))
	return prev
}

// String returns a human-readable representation of the message.
func (m *DHTClientGetMsg) String() string {
	return fmt.Sprintf("DHTClientGetMsg{Id:%d,Type=%s,Options=%d,Repl=%d,Key=%s}",
		m.ID, m.BType, m.Options, m.ReplLevel, m.Key)
}

//----------------------------------------------------------------------
// DHT_CLIENT_RESULT
//----------------------------------------------------------------------

// DHTClientResultMsg is a message for DHT results
type DHTClientResultMsg struct {
	MsgHeader
	BType      enums.BlockType   `order:"big"` // The type for the data
	PutPathLen uint32            `order:"big"` // Number of peers recorded in outgoing path
	GetPathLen uint32            `order:"big"` // Number of peers recorded from storage location
	ID         uint64            `order:"big"` // Unique ID of the matching GET request
	Expire     util.AbsoluteTime // Expiration time
	Key        *crypto.HashCode  // The key that was searched for
	PutPath    []*util.PeerID    `size:"PutPathLen"` // put path
	GetPath    []*util.PeerID    `size:"GetPathLen"` // get path
	Data       []byte            `size:"*"`          // data returned for query
}

// NewDHTClientResultMsg creates a new default DHTClientResultMsg object.
func NewDHTClientResultMsg(key *crypto.HashCode) *DHTClientResultMsg {
	if key == nil {
		key = crypto.NewHashCode(nil)
	}
	return &DHTClientResultMsg{
		MsgHeader:  MsgHeader{64, enums.MSG_DHT_CLIENT_RESULT},
		BType:      0,
		PutPathLen: 0,
		GetPathLen: 0,
		ID:         0,
		Expire:     *new(util.AbsoluteTime),
		Key:        key,
		Data:       make([]byte, 0),
	}
}

// String returns a human-readable representation of the message.
func (m *DHTClientResultMsg) String() string {
	return fmt.Sprintf("DHTClientResultMsg{id:%d,type=%s,expire=%s}", m.ID, m.BType, m.Expire)
}

//----------------------------------------------------------------------
// DHT_CLIENT_GET_STOP
//----------------------------------------------------------------------

// DHTClientGetStopMsg stops a pending DHT operation
type DHTClientGetStopMsg struct {
	MsgHeader
	Reserved uint32           `order:"big"` // Reserved (0)
	ID       uint64           `order:"big"` // Unique ID identifying this request
	Key      *crypto.HashCode // The key to search for
}

// NewDHTClientGetStopMsg creates a new default DHTClientGetStopMsg object.
func NewDHTClientGetStopMsg(key *crypto.HashCode) *DHTClientGetStopMsg {
	if key == nil {
		key = new(crypto.HashCode)
	}
	return &DHTClientGetStopMsg{
		MsgHeader: MsgHeader{80, enums.MSG_DHT_CLIENT_GET_STOP},
		Reserved:  0, // mandatory
		ID:        0,
		Key:       key,
	}
}

// String returns a human-readable representation of the message.
func (m *DHTClientGetStopMsg) String() string {
	return fmt.Sprintf("DHTClientGetStopMsg{Id:%d,Key=%s}", m.ID, m.Key)
}

//----------------------------------------------------------------------
// DHT_CLIENT_GET_RESULTS_KNOWN
//----------------------------------------------------------------------

// DHTClientGetResultsKnownMsg is the message for putting values into the DHT
type DHTClientGetResultsKnownMsg struct {
	MsgHeader
	Reserved uint32             `order:"big"` // Reserved for further use
	Key      *crypto.HashCode   // The key to search for
	ID       uint64             `order:"big"` // Unique ID identifying this request
	Known    []*crypto.HashCode `size:"*"`    // list of known results
}

// NewDHTClientPutMsg creates a new default DHTClientPutMsg object.
func NewDHTClientGetResultsKnownMsg(key *crypto.HashCode) *DHTClientGetResultsKnownMsg {
	if key == nil {
		key = new(crypto.HashCode)
	}
	return &DHTClientGetResultsKnownMsg{
		MsgHeader: MsgHeader{80, enums.MSG_DHT_CLIENT_GET_RESULTS_KNOWN},
		Key:       key,
		ID:        0,
		Known:     make([]*crypto.HashCode, 0),
	}
}

// AddKnown adds a known result to the list
func (m *DHTClientGetResultsKnownMsg) AddKnown(hc *crypto.HashCode) {
	m.Known = append(m.Known, hc)
	m.MsgSize += 64
}

// String returns a human-readable representation of the message.
func (m *DHTClientGetResultsKnownMsg) String() string {
	return fmt.Sprintf("DHTClientGetResultsKnownMsg{Id:%d,Key=%s,Num=%d}",
		m.ID, m.Key.Data, len(m.Known))
}
