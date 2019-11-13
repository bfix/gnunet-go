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
