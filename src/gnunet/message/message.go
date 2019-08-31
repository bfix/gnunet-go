package message

import (
	"errors"

	"github.com/bfix/gospel/data"
)

var (
	ErrMsgHeaderTooSmall = errors.New("Message header too small")
)

type Message interface {
	Header() *MessageHeader
}

type MessageHeader struct {
	MsgSize uint16 `order:"big"`
	MsgType uint16 `order:"big"`
}

func (mh *MessageHeader) Size() uint16 {
	return mh.MsgSize
}

func (mh *MessageHeader) Type() uint16 {
	return mh.MsgType
}

func GetMsgHeader(b []byte) (mh *MessageHeader, err error) {
	if b == nil || len(b) < 4 {
		return nil, ErrMsgHeaderTooSmall
	}
	mh = new(MessageHeader)
	err = data.Unmarshal(mh, b)
	return
}
