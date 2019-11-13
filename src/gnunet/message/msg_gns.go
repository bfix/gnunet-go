package message

import (
	"fmt"

	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
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
	Options  uint16 `order:"big"` // Local options for where to look for results
	Reserved uint16 `order:"big"` // Always 0
	Type     uint32 `order:"big"` // the type of record to look up
	Name     []byte `size:"*"`    // zero-terminated name to look up
}

// NewGNSLookupMsg creates a new default message.
func NewGNSLookupMsg() *GNSLookupMsg {
	return &GNSLookupMsg{
		MsgSize:  48, // record size with no name
		MsgType:  GNS_LOOKUP,
		Id:       0,
		Zone:     make([]byte, 32),
		Options:  uint16(enums.GNS_LO_DEFAULT),
		Reserved: 0,
		Type:     uint32(enums.GNS_TYPE_ANY),
		Name:     nil,
	}
}

// SetName appends the name to lookup to the message
func (m *GNSLookupMsg) SetName(name string) {
	m.Name = util.Clone(append([]byte(name), 0))
	m.MsgSize = uint16(48 + len(m.Name))
}

// GetName returns the name to lookup from the message
func (m *GNSLookupMsg) GetName() string {
	size := len(m.Name)
	if m.Name[size-1] != 0 {
		logger.Println(logger.WARN, "GNS_LOOKUP name not NULL-terminated")
	} else {
		size -= 1
	}
	return string(m.Name[:size])
}

// String returns a human-readable representation of the message.
func (m *GNSLookupMsg) String() string {
	return fmt.Sprintf(
		"GNSLookupMsg{Id=%d,Zone=%s,Options=%d,Type=%d,Name=%s}",
		m.Id, util.EncodeBinaryToString(m.Zone),
		m.Options, m.Type, m.GetName())
}

// Header returns the message header in a separate instance.
func (msg *GNSLookupMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// GNS_LOOKUP_RESULT
//----------------------------------------------------------------------

// GNSResourceRecord is the GNUnet-specific representation of resource
// records (not to be confused with DNS resource records).
type GNSResourceRecord struct {
	Expires util.AbsoluteTime // Expiration time for the record
	Size    uint32            `order:"big"` // Number of bytes in 'Data'
	Type    uint32            `order:"big"` // Type of the GNS/DNS record
	Flags   uint32            `order:"big"` // Flags for the record
	Data    []byte            `size:"Size"` // Record data
}

// String returns a human-readable representation of the message.
func (r *GNSResourceRecord) String() string {
	return fmt.Sprintf("GNSResourceRecord{type=%s,expire=%s,flags=%d,size=%d}",
		enums.GNS_TYPE[int(r.Type)], r.Expires, r.Flags, r.Size)
}

// GNSLookupResultMsg
type GNSLookupResultMsg struct {
	MsgSize uint16               `order:"big"`  // total size of message
	MsgType uint16               `order:"big"`  // GNS_LOOKUP_RESULT (501)
	Id      uint32               `order:"big"`  // Unique identifier for this request (for key collisions).
	Count   uint32               `order:"big"`  // The number of records contained in response
	Records []*GNSResourceRecord `size:"Count"` // GNS resource records
}

// NewGNSLookupResultMsg
func NewGNSLookupResultMsg(id uint32) *GNSLookupResultMsg {
	return &GNSLookupResultMsg{
		MsgSize: 12, // Empty result (no records)
		MsgType: GNS_LOOKUP_RESULT,
		Id:      id,
		Count:   0,
		Records: make([]*GNSResourceRecord, 0),
	}
}

// AddRecord adds a GNS resource recordto the response message.
func (m *GNSLookupResultMsg) AddRecord(rec *GNSResourceRecord) error {
	recSize := 20 + int(rec.Size)
	if int(m.MsgSize)+recSize > enums.GNS_MAX_BLOCK_SIZE {
		return fmt.Errorf("gns.AddRecord(): MAX_BLOCK_SIZE reached")
	}
	m.Records = append(m.Records, rec)
	m.MsgSize += uint16(recSize)
	m.Count++
	return nil
}

// String returns a human-readable representation of the message.
func (m *GNSLookupResultMsg) String() string {
	return fmt.Sprintf("GNSLookupResultMsg{Id=%d,Count=%d}", m.Id, m.Count)
}

// Header returns the message header in a separate instance.
func (msg *GNSLookupResultMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}
