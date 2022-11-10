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
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"
)

//----------------------------------------------------------------------
// MSG_IDENTITY_START
//
// Start client connection for update notification. Triggers sending
// all identities as update messages to client.
//----------------------------------------------------------------------

// IdentityStartMsg to initiate session.
type IdentityStartMsg struct {
	MsgHeader
}

// NewIdentityStartMsg creates an empty message
func NewIdentityStartMsg() *IdentityStartMsg {
	return &IdentityStartMsg{
		MsgHeader: MsgHeader{4, enums.MSG_IDENTITY_START},
	}
}

// Init called after unmarshalling a message to setup internal state
func (msg *IdentityStartMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (msg *IdentityStartMsg) String() string {
	return "IdentityStartMsg{}"
}

//----------------------------------------------------------------------
// MSG_IDENTITY_UPDATE
//
// IdentityStore changed (send to all clients with started session)
//----------------------------------------------------------------------

// IdentityUpdateMsg notifies about changes in identity store
type IdentityUpdateMsg struct {
	MsgHeader

	NameLen  uint16              `order:"big"`                // length of name
	EOL      uint16              `order:"big"`                // flag for "end-of-list"
	KeyLen   uint16              `order:"big"`                // length of key
	Reserved uint16              `order:"big"`                // reserved
	Name_    []byte              `size:"NameLen"`             // label name
	ZoneKey  *crypto.ZonePrivate `init:"Init" opt:"(IsUsed)"` // zone key

	// transient state
	name string
}

// IsUsed to decide if key is used in message
func (msg *IdentityUpdateMsg) IsUsed(fld string) bool {
	return msg.EOL != uint16(enums.RC_YES)
}

// NewIdentityUpdateMsg creates an update message. If the zone key is nil,
// a End-Of-List is triggered so the client knows we are done.
func NewIdentityUpdateMsg(name string, zk *crypto.ZonePrivate) *IdentityUpdateMsg {
	var kl uint16
	if zk != nil {
		kl = uint16(zk.KeySize() + 4)
	}
	nl := uint16(len(name) + 1)
	size := kl + nl + 12
	msg := &IdentityUpdateMsg{
		MsgHeader: MsgHeader{size, enums.MSG_IDENTITY_UPDATE},
		name:      name,
		Name_:     util.WriteCString(name),
		NameLen:   nl,
		KeyLen:    kl,
	}
	if zk == nil {
		// tag end-of-list
		msg.EOL = uint16(enums.RC_YES)
	} else {
		msg.ZoneKey = zk
	}
	return msg
}

// Init called after unmarshalling a message to setup internal state
func (msg *IdentityUpdateMsg) Init() error {
	msg.name, _ = util.ReadCString(msg.Name_, 0)
	return nil
}

// String returns a human-readable representation of the message.
func (msg *IdentityUpdateMsg) String() string {
	if msg.EOL == uint16(enums.RC_OK) {
		return "IdentityUpdateMsg{end-of-list}"
	}
	return fmt.Sprintf("IdentityUpdateMsg{'%s'@%s}", msg.Name(), msg.ZoneKey.ID())
}

// Name of the new identity
func (msg *IdentityUpdateMsg) Name() string {
	return msg.name
}

//----------------------------------------------------------------------
// MSG_IDENTITY_RESULT_CODE
//
// Returned by CREATE and RENAME (and by GET_DEFAULT on failure).
//----------------------------------------------------------------------

// IdentityResultCodeMsg is a response message
type IdentityResultCodeMsg struct {
	MsgHeader

	ResultCode uint32 `order:"big"`
}

// Init called after unmarshalling a message to setup internal state
func (msg *IdentityResultCodeMsg) Init() error { return nil }

// NewIdentityResultCodeMsg creates a new default message.
func NewIdentityResultCodeMsg(rc int) *IdentityResultCodeMsg {
	msg := &IdentityResultCodeMsg{
		MsgHeader: MsgHeader{
			MsgSize: 8,
			MsgType: enums.MSG_IDENTITY_RESULT_CODE,
		},
		ResultCode: uint32(rc),
	}
	return msg
}

// String returns a human-readable representation of the message.
func (msg *IdentityResultCodeMsg) String() string {
	return fmt.Sprintf("IdentityResultCodeMsg{rc=%d}", msg.ResultCode)
}

//----------------------------------------------------------------------
// MSG_IDENTITY_CREATE
//
// Create new identity with service association
//----------------------------------------------------------------------

// IdentityCreateMsg to create a new identity for given service
type IdentityCreateMsg struct {
	MsgHeader

	NameLen uint16              `order:"big"`    // length of label name
	KeyLen  uint16              `order:"big"`    // length of key
	ZoneKey *crypto.ZonePrivate `init:"Init"`    // zone key
	Name_   []byte              `size:"NameLen"` // label name

	// transient state
	name string
}

// Init called after unmarshalling a message to setup internal state
func (msg *IdentityCreateMsg) Init() error {
	msg.name, _ = util.ReadCString(msg.Name_, 0)
	return nil
}

// NewIdentityCreateMsg creates a new default message.
func NewIdentityCreateMsg(zk *crypto.ZonePrivate, name string) *IdentityCreateMsg {
	var size uint16
	if zk == nil {
		zk, size = crypto.NullZonePrivate(enums.GNS_TYPE_PKEY)
	} else {
		size = uint16(zk.KeySize() + 4)
	}
	msg := &IdentityCreateMsg{
		MsgHeader: MsgHeader{
			MsgSize: size + 8,
			MsgType: enums.MSG_IDENTITY_CREATE,
		},
		ZoneKey: zk,
	}
	if len(name) > 0 {
		msg.Name_ = util.WriteCString(name)
		msg.MsgSize += uint16(len(msg.Name_))
		msg.name = name
	}
	return msg
}

// String returns a human-readable representation of the message.
func (msg *IdentityCreateMsg) String() string {
	return fmt.Sprintf("IdentityCreateMsg{name='%s',key=%s}", msg.name, msg.ZoneKey.ID())
}

// Name of the new identity
func (msg *IdentityCreateMsg) Name() string {
	return msg.name
}

//----------------------------------------------------------------------
// MSG_IDENTITY_RENAME
//
// Rename identity
//----------------------------------------------------------------------

// IdentitRenameMsg to rename an identity
type IdentityRenameMsg struct {
	MsgHeader

	OldNameLen uint16 `order:"big"`
	NewNameLen uint16 `order:"big"`
	OldName_   []byte `size:"OldNameLen"`
	NewName_   []byte `size:"NewNameLen"`

	// transient state
	oldName string
	newName string
}

// Init called after unmarshalling a message to setup internal state
func (msg *IdentityRenameMsg) Init() error {
	msg.oldName, _ = util.ReadCString(msg.OldName_, 0)
	msg.newName, _ = util.ReadCString(msg.NewName_, 0)
	return nil
}

// NewIdentityRenameMsg renames an identity
func NewIdentityRenameMsg(oldName, newName string) *IdentityRenameMsg {
	msg := &IdentityRenameMsg{
		MsgHeader: MsgHeader{
			MsgSize: 8,
			MsgType: enums.MSG_IDENTITY_RENAME,
		},
	}
	if len(oldName) > 0 {
		msg.OldName_ = util.WriteCString(oldName)
		msg.MsgSize += uint16(len(msg.OldName_))
		msg.oldName = oldName
	}
	if len(newName) > 0 {
		msg.NewName_ = util.WriteCString(newName)
		msg.MsgSize += uint16(len(msg.NewName_))
		msg.newName = newName
	}
	return msg
}

// String returns a human-readable representation of the message.
func (msg *IdentityRenameMsg) String() string {
	return fmt.Sprintf("IdentityRenameMsg{'%s'->'%s'}", msg.oldName, msg.newName)
}

// OldName of the identity
func (msg *IdentityRenameMsg) OldName() string {
	return msg.oldName
}

// NewName of the identity
func (msg *IdentityRenameMsg) NewName() string {
	return msg.newName
}

//----------------------------------------------------------------------
// MSG_IDENTITY_DELETE
//
// Remove named identity
//----------------------------------------------------------------------

// IdentityDeleteMsg requests the deletion of an identity
type IdentityDeleteMsg struct {
	MsgHeader

	NameLen  uint16 `order:"big"`
	Reserved uint16 `order:"big"`
	Name_    []byte `size:"NameLen"`

	// transient state
	name string
}

// Init called after unmarshalling a message to setup internal state
func (msg *IdentityDeleteMsg) Init() error {
	msg.name, _ = util.ReadCString(msg.Name_, 0)
	return nil
}

// NewIdentityDeleteMsg renames an identity
func NewIdentityDeleteMsg(name string) *IdentityDeleteMsg {
	msg := &IdentityDeleteMsg{
		MsgHeader: MsgHeader{
			MsgSize: 8,
			MsgType: enums.MSG_IDENTITY_DELETE,
		},
	}
	if len(name) > 0 {
		msg.Name_ = util.WriteCString(name)
		msg.MsgSize += uint16(len(msg.Name_))
		msg.name = name
	}
	return msg
}

// String returns a human-readable representation of the message.
func (msg *IdentityDeleteMsg) String() string {
	return fmt.Sprintf("IdentityDeleteMsg{name='%s'}", msg.name)
}

// Name of the removed identity
func (msg *IdentityDeleteMsg) Name() string {
	return msg.name
}

//----------------------------------------------------------------------
// MSG_IDENTITY_LOOKUP
//
// Return default identity
//----------------------------------------------------------------------

// IdentityLookupMsg to lookup named identity
type IdentityLookupMsg struct {
	MsgHeader

	Name string
}

// Init called after unmarshalling a message to setup internal state
func (msg *IdentityLookupMsg) Init() error {
	return nil
}

// NewIdentityLookupMsg renames an identity
func NewIdentityLookupMsg(name string) *IdentityLookupMsg {
	return &IdentityLookupMsg{
		MsgHeader: MsgHeader{
			MsgSize: uint16(len(name) + 9),
			MsgType: enums.MSG_IDENTITY_DELETE,
		},
		Name: name,
	}
}

// String returns a human-readable representation of the message.
func (msg *IdentityLookupMsg) String() string {
	return fmt.Sprintf("IdentityLookupMsg{name='%s'}", msg.Name)
}
