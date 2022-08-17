// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2022 Bernd Fix  >Y<
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
	"gnunet/enums"

	"github.com/bfix/gospel/data"
)

// Error codes
var (
	ErrMsgHeaderTooSmall = errors.New("Message header too small")
)

//----------------------------------------------------------------------

// Message is an interface for all GNUnet-specific messages.
type Message interface {

	// Size returns the size of the full message
	Size() uint16

	// Type returns the message type (defines the layout of the body data)
	Type() enums.MsgType

	// String returns a human-readable message
	String() string
}

//----------------------------------------------------------------------

// MsgHeader encapsulates the common part of all GNUnet messages (at the
// beginning of the data).
type MsgHeader struct {
	MsgSize uint16        `order:"big"`
	MsgType enums.MsgType `order:"big"`
}

// Size returns the total size of the message (header + body)
func (mh *MsgHeader) Size() uint16 {
	return mh.MsgSize
}

// Type returns the message type (defines the layout of the body data)
func (mh *MsgHeader) Type() enums.MsgType {
	return mh.MsgType
}

// GetMsgHeader returns the header of a message from a byte array (as the
// serialized form).
func GetMsgHeader(b []byte) (mh *MsgHeader, err error) {
	if b == nil || len(b) < 4 {
		return nil, ErrMsgHeaderTooSmall
	}
	mh = new(MsgHeader)
	err = data.Unmarshal(mh, b)
	return
}
