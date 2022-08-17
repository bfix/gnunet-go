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
// REVOCATION_QUERY
//----------------------------------------------------------------------

// RevocationQueryMsg is a request message to check if a key is revoked
type RevocationQueryMsg struct {
	MsgHeader
	Reserved uint32          `order:"big"` // Reserved for future use
	Zone     *crypto.ZoneKey // Zone that is to be checked for revocation
}

// NewRevocationQueryMsg creates a new message for a given zone.
func NewRevocationQueryMsg(zkey *crypto.ZoneKey) *RevocationQueryMsg {
	return &RevocationQueryMsg{
		MsgHeader: MsgHeader{40, enums.MSG_REVOCATION_QUERY},
		Reserved:  0,
		Zone:      zkey,
	}
}

// String returns a human-readable representation of the message.
func (m *RevocationQueryMsg) String() string {
	return fmt.Sprintf("RevocationQueryMsg{zone=%s}", m.Zone.ID())
}

//----------------------------------------------------------------------
// REVOCATION_QUERY_RESPONSE
//----------------------------------------------------------------------

// RevocationQueryResponseMsg is a response message for revocation checks.
type RevocationQueryResponseMsg struct {
	MsgHeader
	Valid uint32 `order:"big"` // revoked(0), valid(1)
}

// NewRevocationQueryResponseMsg creates a new response for a query.
func NewRevocationQueryResponseMsg(revoked bool) *RevocationQueryResponseMsg {
	valid := 1
	if revoked {
		valid = 0
	}
	return &RevocationQueryResponseMsg{
		MsgHeader: MsgHeader{8, enums.MSG_REVOCATION_QUERY_RESPONSE},
		Valid:     uint32(valid),
	}
}

// String returns a human-readable representation of the message.
func (m *RevocationQueryResponseMsg) String() string {
	return fmt.Sprintf("RevocationQueryResponseMsg{valid=%d}", m.Valid)
}

//----------------------------------------------------------------------
// REVOCATION_REVOKE
//----------------------------------------------------------------------

// RevocationRevokeMsg is a request to revoke a given key with PoW data
type RevocationRevokeMsg struct {
	MsgHeader
	Timestamp  util.AbsoluteTime     ``                      // Timestamp of revocation creation
	TTL        util.RelativeTime     ``                      // TTL of revocation
	PoWs       []uint64              `size:"32" order:"big"` // (Sorted) list of PoW values
	ZoneKeySig *crypto.ZoneSignature ``                      // public zone key (with signature) to be revoked
}

// NewRevocationRevokeMsg creates a new message for a given zone.
func NewRevocationRevokeMsg(zsig *crypto.ZoneSignature) *RevocationRevokeMsg {
	return &RevocationRevokeMsg{
		MsgHeader:  MsgHeader{364, enums.MSG_REVOCATION_REVOKE},
		Timestamp:  util.AbsoluteTimeNow(),
		TTL:        util.RelativeTime{},
		PoWs:       make([]uint64, 32),
		ZoneKeySig: zsig,
	}
}

// String returns a human-readable representation of the message.
func (m *RevocationRevokeMsg) String() string {
	return fmt.Sprintf("RevocationRevokeMsg{zone=%s,expire=%s}",
		m.ZoneKeySig.ID(), m.Timestamp.AddRelative(m.TTL))
}

//----------------------------------------------------------------------
// REVOCATION_REVOKE_RESPONSE
//----------------------------------------------------------------------

// RevocationRevokeResponseMsg is a response message for a revocation request
type RevocationRevokeResponseMsg struct {
	MsgHeader
	Success uint32 `order:"big"` // Revoke successful? (0=no, 1=yes)
}

// NewRevocationRevokeResponseMsg creates a new response for a query.
func NewRevocationRevokeResponseMsg(success bool) *RevocationRevokeResponseMsg {
	status := 0
	if success {
		status = 1
	}
	return &RevocationRevokeResponseMsg{
		MsgHeader: MsgHeader{8, enums.MSG_REVOCATION_QUERY_RESPONSE},
		Success:   uint32(status),
	}
}

// String returns a human-readable representation of the message.
func (m *RevocationRevokeResponseMsg) String() string {
	return fmt.Sprintf("RevocationRevokeResponseMsg{success=%v}", m.Success == 1)
}
