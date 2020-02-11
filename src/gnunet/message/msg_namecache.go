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
	"gnunet/util"
)

//----------------------------------------------------------------------
// NAMECACHE_LOOKUP_BLOCK
//----------------------------------------------------------------------

// NamecacheLookupMsg
type NamecacheLookupMsg struct {
	MsgSize uint16           `order:"big"` // total size of message
	MsgType uint16           `order:"big"` // NAMECACHE_LOOKUP_BLOCK (431)
	Id      uint32           `order:"big"` // Request Id
	Query   *crypto.HashCode // Query data
}

// NewNamecacheLookupMsg creates a new default message.
func NewNamecacheLookupMsg(query *crypto.HashCode) *NamecacheLookupMsg {
	if query == nil {
		query = crypto.NewHashCode()
	}
	return &NamecacheLookupMsg{
		MsgSize: 72,
		MsgType: NAMECACHE_LOOKUP_BLOCK,
		Id:      0,
		Query:   query,
	}
}

// String returns a human-readable representation of the message.
func (m *NamecacheLookupMsg) String() string {
	return fmt.Sprintf("NamecacheLookupMsg{Id=%d,Query=%s}",
		m.Id, hex.EncodeToString(m.Query.Bits))
}

// Header returns the message header in a separate instance.
func (msg *NamecacheLookupMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// NAMECACHE_LOOKUP_BLOCK_RESPONSE
//----------------------------------------------------------------------

// NamecacheLookupResultMsg
type NamecacheLookupResultMsg struct {
	MsgSize    uint16            `order:"big"` // total size of message
	MsgType    uint16            `order:"big"` // NAMECACHE_LOOKUP_BLOCK_RESPONSE (432)
	Id         uint32            `order:"big"` // Request Id
	Expire     util.AbsoluteTime // Expiration time
	Signature  []byte            `size:"64"` // ECDSA signature
	DerivedKey []byte            `size:"32"` // Derived public key
	EncData    []byte            `size:"*"`  // Encrypted block data
}

// NewNamecacheLookupResultMsg creates a new default message.
func NewNamecacheLookupResultMsg() *NamecacheLookupResultMsg {
	return &NamecacheLookupResultMsg{
		MsgSize:    112,
		MsgType:    NAMECACHE_LOOKUP_BLOCK_RESPONSE,
		Id:         0,
		Expire:     *new(util.AbsoluteTime),
		Signature:  make([]byte, 64),
		DerivedKey: make([]byte, 32),
		EncData:    make([]byte, 0),
	}
}

// String returns a human-readable representation of the message.
func (m *NamecacheLookupResultMsg) String() string {
	return fmt.Sprintf("NamecacheLookupResultMsg{id=%d,expire=%s}",
		m.Id, m.Expire)
}

// Header returns the message header in a separate instance.
func (msg *NamecacheLookupResultMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// NAMECACHE_CACHE_BLOCK
//----------------------------------------------------------------------

// NamecacheCacheMsg
type NamecacheCacheMsg struct {
	MsgSize    uint16            `order:"big"` // total size of message
	MsgType    uint16            `order:"big"` // NAMECACHE_CACHE_BLOCK (433)
	Id         uint32            `order:"big"` // Request Id
	Expire     util.AbsoluteTime // Expiration time
	Signature  []byte            `size:"64"` // ECDSA signature
	DerivedKey []byte            `size:"32"` // Derived public key
	EncData    []byte            `size:"*"`  // Encrypted block data
}

// NewNamecacheLookupMsg creates a new default message.
func NewNamecacheCacheMsg(block *GNSBlock) *NamecacheCacheMsg {
	msg := &NamecacheCacheMsg{
		MsgSize:    108,
		MsgType:    NAMECACHE_BLOCK_CACHE,
		Id:         0,
		Expire:     *new(util.AbsoluteTime),
		Signature:  make([]byte, 64),
		DerivedKey: make([]byte, 32),
		EncData:    make([]byte, 0),
	}
	if block != nil {
		msg.Expire = block.Block.Expire
		copy(msg.Signature, block.Signature)
		copy(msg.DerivedKey, block.DerivedKey)
		size := len(block.Block.EncData)
		msg.EncData = make([]byte, size)
		copy(msg.EncData, block.Block.EncData)
		msg.MsgSize += uint16(size)
	}
	return msg
}

// String returns a human-readable representation of the message.
func (m *NamecacheCacheMsg) String() string {
	return fmt.Sprintf("NewNamecacheCacheMsg{id=%d,expire=%s}",
		m.Id, m.Expire)
}

// Header returns the message header in a separate instance.
func (msg *NamecacheCacheMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// NAMECACHE_BLOCK_CACHE_RESPONSE
//----------------------------------------------------------------------

// NamecacheCacheResponseMsg
type NamecacheCacheResponseMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // NAMECACHE_LOOKUP_BLOCK_RESPONSE (432)
	Id      uint32 `order:"big"` // Request Id
	Result  int32  `order:"big"` // Result code
}

// NewNamecacheCacheResponseMsg creates a new default message.
func NewNamecacheCacheResponseMsg() *NamecacheCacheResponseMsg {
	return &NamecacheCacheResponseMsg{
		MsgSize: 12,
		MsgType: NAMECACHE_BLOCK_CACHE_RESPONSE,
		Id:      0,
		Result:  0,
	}
}

// String returns a human-readable representation of the message.
func (m *NamecacheCacheResponseMsg) String() string {
	return fmt.Sprintf("NamecacheCacheResponseMsg{id=%d,result=%d}",
		m.Id, m.Result)
}

// Header returns the message header in a separate instance.
func (msg *NamecacheCacheResponseMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}
