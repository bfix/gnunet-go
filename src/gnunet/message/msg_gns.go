package message

import (
	"fmt"

	"gnunet/enums"
	"gnunet/util"
)

//----------------------------------------------------------------------
// GNS_LOOKUP
//----------------------------------------------------------------------

// GNSLookupMsg
type GNSLookupMsg struct {
	MsgSize  uint16 `order:"big"` // total size of message
	MsgType  uint16 `order:"big"` // GNS_LOOKUP (500)
	Id       uint32 `order:"big"` // Unique identifier for this request (for key collisions).
	Zone     []byte `size:"32"`   // Zone that is to be used for lookup
	Options  int16  `order:"big"` // Local options for where to look for results
	Reserved int16  `order:"big"` // Always 0
	Type     int32  `order:"big"` // the type of record to look up
	Name     []byte `size:"*"`    // zero-terminated name to look up
}

// NewGNSLookupMsg creates a new default message.
func NewGNSLookupMsg() *GNSLookupMsg {
	return &GNSLookupMsg{
		MsgSize:  48, // record size with no name
		MsgType:  GNS_LOOKUP,
		Id:       0,
		Zone:     make([]byte, 32),
		Options:  int16(enums.GNS_LO_DEFAULT),
		Reserved: 0,
		Type:     int32(enums.GNS_TYPE_ANY),
		Name:     nil,
	}
}

// SetName
func (m *GNSLookupMsg) SetName(name string) {
	m.Name = util.Clone(append([]byte(name), 0))
	m.MsgSize = uint16(48 + len(m.Name))
}

// String
func (m *GNSLookupMsg) String() string {
	return fmt.Sprintf(
		"GNSLookupMsg{Id=%d,Zone=%s,Options=%d,Type=%d,Name=%s}",
		m.Id, util.EncodeBinaryToString(m.Zone),
		m.Options, m.Type, string(m.Name))
}

// Header returns the message header in a separate instance.
func (msg *GNSLookupMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}
