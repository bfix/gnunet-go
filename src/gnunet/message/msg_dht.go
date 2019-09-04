package message

import (
	"fmt"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"
)

//----------------------------------------------------------------------
// DHT_CLIENT_GET
//----------------------------------------------------------------------

// DHTClientGetMsg
type DHTClientGetMsg struct {
	MsgSize   uint16           `order:"big"` // total size of message
	MsgType   uint16           `order:"big"` // DHT_CLIENT_GET (143)
	Options   uint32           `order:"big"` // Message options (DHT_RO_???)
	ReplLevel uint32           `order:"big"` // Replication level for this message
	Type      uint32           `order:"big"` // The type for the data for the GET request (BLOCK_TYPE_???)
	Key       *crypto.HashCode // The key to search for
	Id        uint64           `order:"big"` // Unique ID identifying this request
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
		Id:        0,
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
	return fmt.Sprintf("DHTClientGetMsg{id:%16x}", m.Id)
}

// Header returns the message header in a separate instance.
func (msg *DHTClientGetMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// DHT_CLIENT_RESULT
//----------------------------------------------------------------------

// DHTClientResultMsg
type DHTClientResultMsg struct {
	MsgSize    uint16           `order:"big"` // total size of message
	MsgType    uint16           `order:"big"` // DHT_CLIENT_RESULT (145)
	Type       uint32           `order:"big"` // The type for the data
	PutPathLen uint32           `order:"big"` // Number of peers recorded in outgoing path
	GetPathLen uint32           `order:"big"` // Number of peers recorded from storage location
	Id         uint64           `order:"big"` // Unique ID of the matching GET request
	Expire     uint64           `order:"big"` // Expiration time
	Key        *crypto.HashCode // The key that was searched for
	Data       []byte           `size:"*"` // put path, get path and actual data
}

// NewDHTClientResultMsg creates a new default DHTClientResultMsg object.
func NewDHTClientResultMsg() *DHTClientResultMsg {
	return &DHTClientResultMsg{
		MsgSize: 64, // empty message size (no data)
		MsgType: DHT_CLIENT_RESULT,
	}
}

func (m *DHTClientResultMsg) String() string {
	return fmt.Sprintf("DHTClientResultMsg{id:%16x}", m.Id)
}

// Header returns the message header in a separate instance.
func (msg *DHTClientResultMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}
