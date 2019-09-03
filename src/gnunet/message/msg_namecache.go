package message

import (
	"encoding/hex"
	"fmt"

	//"github.com/bfix/gospel/logger"
	"gnunet/crypto"
	//"gnunet/enums"
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
	return &NamecacheLookupMsg{
		MsgSize: 72,
		MsgType: NAMECACHE_LOOKUP_BLOCK,
		Id:      0,
		Query:   query,
	}
}

// String
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
	MsgSize    uint16 `order:"big"` // total size of message
	MsgType    uint16 `order:"big"` // NAMECACHE_LOOKUP_BLOCK_RESPONSE (432)
	Expire     uint64 `order:"big"` // Expiration time
	Signature  []byte `size:"64"`   // ECDSA signature
	DerivedKey []byte `size:"32"`   // Derived public key
	EncData    []byte `size:"*"`    // Encrypted block data
}

// NewNamecacheLookupResultMsg creates a new default message.
func NewNamecacheLookupResultMsg() *NamecacheLookupResultMsg {
	return &NamecacheLookupResultMsg{
		MsgSize:    108,
		MsgType:    NAMECACHE_LOOKUP_BLOCK_RESPONSE,
		Expire:     0,
		Signature:  make([]byte, 64),
		DerivedKey: make([]byte, 32),
		EncData:    make([]byte, 0),
	}
}

// String
func (m *NamecacheLookupResultMsg) String() string {
	return fmt.Sprintf("NamecacheLookupResultMsg{Expire=%s}",
		util.Timestamp(m.Expire))
}

// Header returns the message header in a separate instance.
func (msg *NamecacheLookupResultMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}
