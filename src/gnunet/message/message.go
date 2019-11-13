package message

import (
	"errors"

	"github.com/bfix/gospel/data"
)

// Error codes
var (
	ErrMsgHeaderTooSmall = errors.New("Message header too small")
)

// Message is an interface for all GNUnet-specific messages.
type Message interface {
	Header() *MessageHeader
}

// MessageHeader encapsulates the common part of all GNUnet messages (at the
// beginning of the data).
type MessageHeader struct {
	MsgSize uint16 `order:"big"`
	MsgType uint16 `order:"big"`
}

// Size returns the total size of the message (header + body)
func (mh *MessageHeader) Size() uint16 {
	return mh.MsgSize
}

// Type returns the message type (defines the layout of the body data)
func (mh *MessageHeader) Type() uint16 {
	return mh.MsgType
}

// GetMsgHeader returns the header of a message from a byte array (as the
// serialized form).
func GetMsgHeader(b []byte) (mh *MessageHeader, err error) {
	if b == nil || len(b) < 4 {
		return nil, ErrMsgHeaderTooSmall
	}
	mh = new(MessageHeader)
	err = data.Unmarshal(mh, b)
	return
}
