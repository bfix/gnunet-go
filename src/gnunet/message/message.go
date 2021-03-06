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
