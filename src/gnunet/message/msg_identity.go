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

	NameLen uint16              `order:"big"`
	EOL     uint16              `order:"big"`
	ZoneKey *crypto.ZonePrivate `init:"Init"`
	Name    []byte              `size:"NameLen"`
}

// NewIdentityUpdateMsg creates an update message. If the zone key is nil,
// a End-Of-List is triggered so the client knows we are done.
func NewIdentityUpdateMsg(name string, zk *crypto.ZonePrivate) *IdentityUpdateMsg {
	msg := &IdentityUpdateMsg{
		MsgHeader: MsgHeader{8, enums.MSG_IDENTITY_UPDATE},
	}
	if zk == nil {
		// tag end-of-list
		msg.EOL = uint16(enums.RC_YES)
		var size uint16
		// assemble an empty zonekey
		msg.ZoneKey, size = crypto.NullZonePrivate(enums.GNS_TYPE_PKEY)
		msg.MsgSize += size
	} else {
		msg.Name = util.WriteCString(name)
		msg.NameLen = uint16(len(msg.Name))
		msg.MsgSize += msg.NameLen
		msg.ZoneKey = zk
		msg.MsgSize += uint16(zk.KeySize() + 4)
	}
	return msg
}

// Init called after unmarshalling a message to setup internal state
func (msg *IdentityUpdateMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (msg *IdentityUpdateMsg) String() string {
	if msg.EOL == uint16(enums.RC_OK) {
		return "IdentityUpdateMsg{end-of-list}"
	}
	name, _ := util.ReadCString(msg.Name, 0)
	return fmt.Sprintf("IdentityUpdateMsg{'%s'@%s}", name, msg.ZoneKey.ID())
}

//----------------------------------------------------------------------
// MSG_IDENTITY_RESULT_CODE
//
// Returned by CREATE and RENAME (and by GET_DEFAULT on failure).
//----------------------------------------------------------------------

// IdentityResultCodeMsg is a response message
type IdentityResultCodeMsg struct {
	MsgHeader

	ResultCode enums.ResultCode `order:"big"`
	Error      string           `opt:"(OnError)"`
}

// OnError returns true if an error message is attached
func (msg *IdentityResultCodeMsg) OnError() bool {
	return msg.ResultCode != enums.RC_OK
}

// Init called after unmarshalling a message to setup internal state
func (msg *IdentityResultCodeMsg) Init() error { return nil }

// NewNamecacheLookupMsg creates a new default message.
func NewIdentityResultCodeMsg(rc enums.ResultCode, err string) *IdentityResultCodeMsg {
	msg := &IdentityResultCodeMsg{
		MsgHeader: MsgHeader{
			MsgSize: 8,
			MsgType: enums.MSG_IDENTITY_RESULT_CODE,
		},
		ResultCode: rc,
	}
	if rc != enums.RC_OK {
		msg.Error = err
		msg.MsgSize += uint16(len(err) + 1)
	}
	return msg
}

// String returns a human-readable representation of the message.
func (msg *IdentityResultCodeMsg) String() string {
	return fmt.Sprintf("IdentityResultCodeMsg{rc=%d,err='%s'}", msg.ResultCode, msg.Error)
}

//----------------------------------------------------------------------
// MSG_IDENTITY_CREATE
//
// Create new identity with service association
//----------------------------------------------------------------------

// IdentityCreateMsg to create a new identity for given service
type IdentityCreateMsg struct {
	MsgHeader

	SrvLen   uint16              `order:"big"`
	Reserved uint16              `order:"big"`
	ZoneKey  *crypto.ZonePrivate `init:"Init"`
	Service  []byte              `size:"SrvLen"`
}

// Init called after unmarshalling a message to setup internal state
func (msg *IdentityCreateMsg) Init() error { return nil }

// NewNamecacheCreateMsg creates a new default message.
func NewIdentityCreateMsg(zk *crypto.ZonePrivate, svc string) *IdentityCreateMsg {
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
	if len(svc) > 0 {
		msg.Service = util.WriteCString(svc)
		msg.MsgSize += uint16(len(msg.Service))
	}
	return msg
}

// String returns a human-readable representation of the message.
func (msg *IdentityCreateMsg) String() string {
	svc, _ := util.ReadCString(msg.Service, 0)
	zk := ""
	if !util.IsAll(msg.ZoneKey.KeyData, 0) {
		zk = fmt.Sprintf(",zk=%s", msg.ZoneKey.ID())
	}
	return fmt.Sprintf("IdentityCreateMsg{svc='%s'%s}", svc, zk)
}

//----------------------------------------------------------------------
// MSG_IDENTITY_LOOKUP
//
// Return default identity
//----------------------------------------------------------------------

// IdentityLookupMsg to lookup identity
type IdentityLookupMsg struct {
	MsgHeader
}

//----------------------------------------------------------------------
// MSG_IDENTITY_LOOKUP_BY_NAME
//
// Return named identity
//----------------------------------------------------------------------

// IdentityLookupMsg to lookup identity by name
type IdentityLookupByNameMsg struct {
	MsgHeader

	Name string
}

//----------------------------------------------------------------------
// MSG_IDENTITY_GET_DEFAULT
//
// Get the default identity for named subsystem
//----------------------------------------------------------------------

type IdentityGetDefault struct {
	MsgHeader

	SrvLen   uint16 `order:"big"`
	Reserved uint16 `order:"big"`
	Service  []byte `size:"SrvLen"`
}

//----------------------------------------------------------------------
// MSG_IDENTITY_SET_DEFAULT
//
// Set default identity for named subsystem
//----------------------------------------------------------------------

type IdentitySetDefaultMsg struct {
	MsgHeader

	SrvLen   uint16 `order:"big"`
	Reserved uint16 `order:"big"`
	ZoneKey  *crypto.ZonePrivate
	Service  []byte `size:"SrvLen"`
}

//----------------------------------------------------------------------
// MSG_IDENTITY_RENAME
//
// Rename identity
//----------------------------------------------------------------------

type IdentityRenameMsg struct {
	MsgHeader

	OldNameLen uint16 `order:"big"`
	NewNameLen uint16 `order:"big"`
	OldName    []byte `size:"OldNameLen"`
	NewName    []byte `size:"NewNameLen"`
}

//----------------------------------------------------------------------
// MSG_IDENTITY_DELETE
//
// Rename identity
//----------------------------------------------------------------------

type IdentityDeleteMsg struct {
	MsgHeader

	NameLen  uint16 `order:"big"`
	Reserved uint16 `order:"big"`
	Name     []byte `size:"NameLen"`
}
