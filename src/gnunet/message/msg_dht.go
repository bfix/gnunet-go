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
	"encoding/hex"
	"fmt"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"
)

//----------------------------------------------------------------------
// DHT_CLIENT_GET
//----------------------------------------------------------------------

// DHTClientGetMsg is the message for getting values from the DHT
type DHTClientGetMsg struct {
	MsgSize   uint16           `order:"big"` // total size of message
	MsgType   uint16           `order:"big"` // DHT_CLIENT_GET (143)
	Options   uint32           `order:"big"` // Message options (DHT_RO_???)
	ReplLevel uint32           `order:"big"` // Replication level for this message
	Type      uint32           `order:"big"` // The type for the data for the GET request (BLOCK_TYPE_???)
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
		MsgSize:   88,
		MsgType:   DHT_CLIENT_GET,
		Options:   uint32(enums.DHT_RO_NONE),
		ReplLevel: 1,
		Type:      uint32(enums.BLOCK_TYPE_ANY),
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
	return fmt.Sprintf("DHTClientGetMsg{Id:%d,Type=%d,Options=%d,Repl=%d,Key=%s}",
		m.ID, m.Type, m.Options, m.ReplLevel, hex.EncodeToString(m.Key.Bits))
}

// Header returns the message header in a separate instance.
func (m *DHTClientGetMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

//----------------------------------------------------------------------
// DHT_CLIENT_RESULT
//----------------------------------------------------------------------

// DHTClientResultMsg is a message for DHT results
type DHTClientResultMsg struct {
	MsgSize    uint16            `order:"big"` // total size of message
	MsgType    uint16            `order:"big"` // DHT_CLIENT_RESULT (145)
	Type       uint32            `order:"big"` // The type for the data
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
		key = crypto.NewHashCode()
	}
	return &DHTClientResultMsg{
		MsgSize:    64, // empty message size (no data)
		MsgType:    DHT_CLIENT_RESULT,
		Type:       0,
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
	return fmt.Sprintf("DHTClientResultMsg{id:%d,expire=%s}", m.ID, m.Expire)
}

// Header returns the message header in a separate instance.
func (m *DHTClientResultMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

//----------------------------------------------------------------------
// DHT_CLIENT_GET_STOP
//----------------------------------------------------------------------

// DHTClientGetStopMsg stops a pending DHT operation
type DHTClientGetStopMsg struct {
	MsgSize  uint16           `order:"big"` // total size of message
	MsgType  uint16           `order:"big"` // DHT_CLIENT_GET_STOP (144)
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
		MsgSize:  80,
		MsgType:  DHT_CLIENT_GET_STOP,
		Reserved: 0, // mandatory
		ID:       0,
		Key:      key,
	}
}

// String returns a human-readable representation of the message.
func (m *DHTClientGetStopMsg) String() string {
	return fmt.Sprintf("DHTClientGetStopMsg{Id:%d,Key=%s}", m.ID, hex.EncodeToString(m.Key.Bits))
}

// Header returns the message header in a separate instance.
func (m *DHTClientGetStopMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}
