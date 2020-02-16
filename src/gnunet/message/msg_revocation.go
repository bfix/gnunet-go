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
	"fmt"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
)

//----------------------------------------------------------------------
// REVOCATION_QUERY
//----------------------------------------------------------------------

// RevocationQueryMsg
type RevocationQueryMsg struct {
	MsgSize  uint16 `order:"big"` // total size of message
	MsgType  uint16 `order:"big"` // REVOCATION_QUERY (636)
	Reserved uint32 `order:"big"` // Reserved for future use
	Zone     []byte `size:"32"`   // Zone that is to be checked for revocation
}

// NewRevocationQueryMsg creates a new message for a given zone.
func NewRevocationQueryMsg(zone *ed25519.PublicKey) *RevocationQueryMsg {
	msg := &RevocationQueryMsg{
		MsgSize:  40,
		MsgType:  REVOCATION_QUERY,
		Reserved: 0,
		Zone:     make([]byte, 32),
	}
	if zone != nil {
		copy(msg.Zone, zone.Bytes())
	}
	return msg
}

// String returns a human-readable representation of the message.
func (m *RevocationQueryMsg) String() string {
	return fmt.Sprintf("RevocationQueryMsg{zone=%s}", util.EncodeBinaryToString(m.Zone))
}

// Header returns the message header in a separate instance.
func (msg *RevocationQueryMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// REVOCATION_QUERY_RESPONSE
//----------------------------------------------------------------------

// RevocationQueryResponseMsg
type RevocationQueryResponseMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // REVOCATION_QUERY_RESPONSE (637)
	Valid   uint32 `order:"big"` // revoked(0), valid(1)
}

// NewRevocationQueryResponseMsg creates a new response for a query.
func NewRevocationQueryResponseMsg(revoked bool) *RevocationQueryResponseMsg {
	valid := 1
	if revoked {
		valid = 0
	}
	return &RevocationQueryResponseMsg{
		MsgSize: 8,
		MsgType: REVOCATION_QUERY_RESPONSE,
		Valid:   uint32(valid),
	}
}

// String returns a human-readable representation of the message.
func (m *RevocationQueryResponseMsg) String() string {
	return fmt.Sprintf("RevocationQueryResponseMsg{valid=%d}", m.Valid)
}

// Header returns the message header in a separate instance.
func (msg *RevocationQueryResponseMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// REVOCATION_REVOKE
//----------------------------------------------------------------------

// RevocationRevokeMsg
type RevocationRevokeMsg struct {
	MsgSize   uint16                   `order:"big"` // total size of message
	MsgType   uint16                   `order:"big"` // REVOCATION_QUERY (636)
	Reserved  uint32                   `order:"big"` // Reserved for future use
	PoW       uint64                   `order:"big"` // Proof-of-work: nonce that satisfy condition
	Signature []byte                   `size:"64"`   // Signature of the revocation.
	Purpose   *crypto.SignaturePurpose // Size and purpose of signature (8 bytes)
	ZoneKey   []byte                   `size:"32"` // Zone key to be revoked
}

// NewRevocationRevokeMsg creates a new message for a given zone.
func NewRevocationRevokeMsg(pow uint64, zoneKey *ed25519.PublicKey, sig *ed25519.EcSignature) *RevocationRevokeMsg {
	msg := &RevocationRevokeMsg{
		MsgSize:   120,
		MsgType:   REVOCATION_REVOKE,
		Reserved:  0,
		PoW:       pow,
		Signature: make([]byte, 64),
		Purpose: &crypto.SignaturePurpose{
			Size:    40,
			Purpose: enums.SIG_REVOCATION,
		},
		ZoneKey: make([]byte, 32),
	}
	if zoneKey != nil {
		copy(msg.ZoneKey, zoneKey.Bytes())
	}
	if sig != nil {
		copy(msg.Signature, sig.Bytes())
	}
	return msg
}

// String returns a human-readable representation of the message.
func (m *RevocationRevokeMsg) String() string {
	return fmt.Sprintf("RevocationRevokeMsg{pow=%d,zone=%s}", m.PoW, util.EncodeBinaryToString(m.ZoneKey))
}

// Header returns the message header in a separate instance.
func (msg *RevocationRevokeMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// REVOCATION_REVOKE_RESPONSE
//----------------------------------------------------------------------

// RevocationRevokeResponseMsg
type RevocationRevokeResponseMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // REVOCATION_QUERY_RESPONSE (637)
	Success uint32 `order:"big"` // Revoke successful?
}

// NewRevocationRevokeResponseMsg creates a new response for a query.
func NewRevocationRevokeResponseMsg(success bool) *RevocationRevokeResponseMsg {
	status := 0
	if success {
		status = 1
	}
	return &RevocationRevokeResponseMsg{
		MsgSize: 8,
		MsgType: REVOCATION_QUERY_RESPONSE,
		Success: uint32(status),
	}
}

// String returns a human-readable representation of the message.
func (m *RevocationRevokeResponseMsg) String() string {
	return fmt.Sprintf("RevocationRevokeResponseMsg{success=%v}", m.Success == 1)
}

// Header returns the message header in a separate instance.
func (msg *RevocationRevokeResponseMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}
