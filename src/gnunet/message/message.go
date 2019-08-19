package message

import (
	"errors"
)

var (
	ErrMsgHeaderTooSmall = errors.New("Message header too small")
)

type Message interface {
	Size() uint16
	Type() uint16
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

func GetMsgHeader(data []byte) (mh *MessageHeader, err error) {
	if data == nil || len(data) < 4 {
		return nil, ErrMsgHeaderTooSmall
	}
	mh = new(MessageHeader)
	err = Unmarshal(mh, data)
	return
}
