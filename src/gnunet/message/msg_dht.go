package message

import (
	"fmt"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"
)

// DHTClientGetMsg
type DHTClientGetMsg struct {
	MsgSize   uint16           `order:"big"` // total size of message
	MsgType   uint16           `order:"big"` // CORE_EPHEMERAL_KEY (88)
	Options   uint32           `order:"big"` // Message options (DHT_RO_???)
	ReplLevel uint32           `order:"big"` // Replication level for this message
	Type      uint32           `order:"big"` // The type for the data for the GET request (BLOCK_TYPE_???)
	Key       *crypto.HashCode // The key to search for
	UniqueID  uint64           `order:"big"` // Unique ID identifying this request
	XQuery    []byte           `size:"*"`    // Optional xquery
}

// NewDHTClientGetMsg creates a new default DHTClientGetMsg object.
func NewDHTClientGetMsg() *DHTClientGetMsg {
	return &DHTClientGetMsg{
		MsgSize:   88,
		MsgType:   DHT_CLIENT_GET,
		Options:   uint32(enums.DHT_RO_NONE),
		ReplLevel: 1,
		Type:      uint32(enums.BLOCK_TYPE_ANY),
		Key:       new(crypto.HashCode),
		UniqueID:  0,
		XQuery:    make([]byte, 0),
	}
}

// Set a (new) XQuery in this message and return previous XQuery.
func (m *DHTClientGetMsg) SetXQuery(xq []byte) []byte {
	prev := m.XQuery
	m.MsgSize -= uint16(len(prev))
	m.XQuery = util.Clone(xq)
	m.MsgSize += uint16(len(xq))
	return prev
}

func (m *DHTClientGetMsg) String() string {
	return fmt.Sprintf("DHTClientGetMsg{id:%16x}",
		m.UniqueID)
}

// Header returns the message header in a separate instance.
func (msg *DHTClientGetMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}
