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
	"time"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// TRANSPORT_TCP_WELCOME
//----------------------------------------------------------------------

// TransportTCPWelcomeMsg is a welcome message for new TCP connections.
type TransportTCPWelcomeMsg struct {
	MsgHeader
	PeerID *util.PeerID // Peer identity (EdDSA public key)
}

// NewTransportTCPWelcomeMsg creates a new message for a given peer.
func NewTransportTCPWelcomeMsg(peerid *util.PeerID) *TransportTCPWelcomeMsg {
	if peerid == nil {
		peerid = util.NewPeerID(nil)
	}
	return &TransportTCPWelcomeMsg{
		MsgHeader: MsgHeader{36, enums.MSG_TRANSPORT_TCP_WELCOME},
		PeerID:    peerid,
	}
}

// String returns a human-readable representation of the message.
func (m *TransportTCPWelcomeMsg) String() string {
	return fmt.Sprintf("TransportTcpWelcomeMsg{peer=%s}", m.PeerID)
}

// Init called after unmarshalling a message to setup internal state
func (m *TransportTCPWelcomeMsg) Init() error { return nil }

//----------------------------------------------------------------------
// TRANSPORT_PING
//
// Message used to ask a peer to validate receipt (to check an address
// from a HELLO).  Followed by the address we are trying to validate,
// or an empty address if we are just sending a PING to confirm that a
// connection which the receiver (of the PING) initiated is still valid.
//----------------------------------------------------------------------

// TransportPingMsg is a PING request message
type TransportPingMsg struct {
	MsgHeader
	Challenge uint32       // Challenge code (to ensure fresh reply)
	Target    *util.PeerID // EdDSA public key (long-term) of target peer
	Address   []byte       `size:"*"` // encoded address
}

// NewTransportPingMsg creates a new message for given peer with an address to
// be validated.
func NewTransportPingMsg(target *util.PeerID, a *util.Address) *TransportPingMsg {
	if target == nil {
		target = util.NewPeerID(nil)
	}
	m := &TransportPingMsg{
		MsgHeader: MsgHeader{40, enums.MSG_TRANSPORT_PING},
		Challenge: util.RndUInt32(),
		Target:    target,
		Address:   nil,
	}
	if a != nil {
		if addrData, err := data.Marshal(a); err == nil {
			m.Address = addrData
			m.MsgSize += uint16(len(addrData))
		}
	}
	return m
}

// String returns a human-readable representation of the message.
func (m *TransportPingMsg) String() string {
	a := new(util.Address)
	if err := data.Unmarshal(a, m.Address); err != nil {
		logger.Printf(logger.ERROR, "[TransportPingMsg.String] failed: %s", err.Error())
	}
	return fmt.Sprintf("TransportPingMsg{target=%s,addr=%s,challenge=%d}",
		m.Target, a, m.Challenge)
}

// Init called after unmarshalling a message to setup internal state
func (m *TransportPingMsg) Init() error { return nil }

//----------------------------------------------------------------------
// TRANSPORT_PONG
//
// Message used to validate a HELLO.  The challenge is included in the
// confirmation to make matching of replies to requests possible.  The
// signature signs our public key, an expiration time and our address.<p>
//
// This message is followed by our transport address that the PING tried
// to confirm (if we liked it).  The address can be empty (zero bytes)
// if the PING had not address either (and we received the request via
// a connection that we initiated).
//----------------------------------------------------------------------

// SignedAddress is the signed block of data representing a node address
type SignedAddress struct {
	Purpose  *crypto.SignaturePurpose // SIG_TRANSPORT_PONG_OWN
	ExpireOn util.AbsoluteTime        // usec epoch
	AddrSize uint32                   `order:"big"`     // size of address
	Address  []byte                   `size:"AddrSize"` // address
}

// NewSignedAddress creates a new (signable) data block from an address.
func NewSignedAddress(a *util.Address) *SignedAddress {
	// serialize address
	addrData, _ := data.Marshal(a)
	alen := len(addrData)
	addr := &SignedAddress{
		Purpose: &crypto.SignaturePurpose{
			Size:    uint32(alen + 20),
			Purpose: enums.SIG_TRANSPORT_PONG_OWN,
		},
		ExpireOn: util.AbsoluteTimeNow().Add(12 * time.Hour),
		AddrSize: uint32(alen),
		Address:  make([]byte, alen),
	}
	copy(addr.Address, addrData)
	return addr
}

// TransportPongMsg is a response message for a PING request
type TransportPongMsg struct {
	MsgHeader
	Challenge   uint32         // Challenge code (to ensure fresh reply)
	Signature   []byte         `size:"64"` // Signature of address
	SignedBlock *SignedAddress // signed block of data
}

// NewTransportPongMsg creates a response message with an address the replying
// peer wants to be reached.
func NewTransportPongMsg(challenge uint32, a *util.Address) *TransportPongMsg {
	m := &TransportPongMsg{
		MsgHeader:   MsgHeader{72, enums.MSG_TRANSPORT_PONG},
		Challenge:   challenge,
		Signature:   make([]byte, 64),
		SignedBlock: new(SignedAddress),
	}
	if a != nil {
		sa := NewSignedAddress(a)
		m.MsgSize += uint16(sa.Purpose.Size)
		m.SignedBlock = sa
	}
	return m
}

// String returns a human-readable representation of the message.
func (m *TransportPongMsg) String() string {
	a := new(util.Address)
	if err := data.Unmarshal(a, m.SignedBlock.Address); err == nil {
		return fmt.Sprintf("TransportPongMsg{addr=%s,challenge=%d}",
			a, m.Challenge)
	}
	return fmt.Sprintf("TransportPongMsg{addr=<unknown>,%d}", m.Challenge)
}

// Sign the address block of a pong message.
func (m *TransportPongMsg) Sign(prv *ed25519.PrivateKey) error {
	data, err := data.Marshal(m.SignedBlock)
	if err != nil {
		return err
	}
	sig, err := prv.EdSign(data)
	if err != nil {
		return err
	}
	copy(m.Signature, sig.Bytes())
	return nil
}

// Verify the address block of a pong message
func (m *TransportPongMsg) Verify(pub *ed25519.PublicKey) (bool, error) {
	data, err := data.Marshal(m.SignedBlock)
	if err != nil {
		return false, err
	}
	sig, err := ed25519.NewEdSignatureFromBytes(m.Signature)
	if err != nil {
		return false, err
	}
	return pub.EdVerify(data, sig)
}

// Init called after unmarshalling a message to setup internal state
func (m *TransportPongMsg) Init() error { return nil }

//----------------------------------------------------------------------
// TRANSPORT_SESSION_ACK
//----------------------------------------------------------------------

// SessionAckMsg is a message to acknowledge a session request
type SessionAckMsg struct {
	MsgHeader
}

// NewSessionAckMsg creates an new message (no body required).
func NewSessionAckMsg() *SessionAckMsg {
	return &SessionAckMsg{
		MsgHeader: MsgHeader{4, enums.MSG_TRANSPORT_SESSION_ACK},
	}
}

// String returns a human-readable representation of the message.
func (m *SessionAckMsg) String() string {
	return "SessionAck{}"
}

// Init called after unmarshalling a message to setup internal state
func (m *SessionAckMsg) Init() error { return nil }

//----------------------------------------------------------------------
// TRANSPORT_SESSION_SYN
//----------------------------------------------------------------------

// SessionSynMsg is a synchronization request message for sessions
type SessionSynMsg struct {
	MsgHeader
	Reserved  uint32            `order:"big"` // reserved (=0)
	Timestamp util.AbsoluteTime // usec epoch
}

// NewSessionSynMsg creates a SYN request for the a session
func NewSessionSynMsg() *SessionSynMsg {
	return &SessionSynMsg{
		MsgHeader: MsgHeader{16, enums.MSG_TRANSPORT_SESSION_SYN},
		Reserved:  0,
		Timestamp: util.AbsoluteTimeNow(),
	}
}

// String returns a human-readable representation of the message.
func (m *SessionSynMsg) String() string {
	return fmt.Sprintf("SessionSyn{timestamp=%s}", m.Timestamp)
}

// Init called after unmarshalling a message to setup internal state
func (m *SessionSynMsg) Init() error { return nil }

//----------------------------------------------------------------------
// TRANSPORT_SESSION_SYN_ACK
//----------------------------------------------------------------------

// SessionSynAckMsg responds to a SYN request message
type SessionSynAckMsg struct {
	MsgHeader
	Reserved  uint32            `order:"big"` // reserved (=0)
	Timestamp util.AbsoluteTime // usec epoch
}

// NewSessionSynAckMsg is an ACK for a SYN request
func NewSessionSynAckMsg() *SessionSynAckMsg {
	return &SessionSynAckMsg{
		MsgHeader: MsgHeader{16, enums.MSG_TRANSPORT_SESSION_SYN_ACK},
		Reserved:  0,
		Timestamp: util.AbsoluteTimeNow(),
	}
}

// String returns a human-readable representation of the message.
func (m *SessionSynAckMsg) String() string {
	return fmt.Sprintf("SessionSynAck{timestamp=%s}", m.Timestamp)
}

// Init called after unmarshalling a message to setup internal state
func (m *SessionSynAckMsg) Init() error { return nil }

//----------------------------------------------------------------------
// TRANSPORT_SESSION_QUOTA
//----------------------------------------------------------------------

// SessionQuotaMsg is a message to announce quotas for a session
type SessionQuotaMsg struct {
	MsgHeader
	Quota uint32 `order:"big"` // Quota in bytes per second
}

// NewSessionQuotaMsg announces a session quota to the other end of the session.
func NewSessionQuotaMsg(quota uint32) *SessionQuotaMsg {
	m := new(SessionQuotaMsg)
	m.MsgSize = 8
	m.MsgType = enums.MSG_TRANSPORT_SESSION_QUOTA
	if quota > 0 {
		m.Quota = quota
	}
	return m
}

// String returns a human-readable representation of the message.
func (m *SessionQuotaMsg) String() string {
	return fmt.Sprintf("SessionQuotaMsg{%sB/s}", util.Scale1024(uint64(m.Quota)))
}

// Init called after unmarshalling a message to setup internal state
func (m *SessionQuotaMsg) Init() error { return nil }

//----------------------------------------------------------------------
// TRANSPORT_SESSION_KEEPALIVE
//----------------------------------------------------------------------

// SessionKeepAliveMsg is a message send by peers to keep a session alive.
type SessionKeepAliveMsg struct {
	MsgHeader
	Nonce uint32
}

// NewSessionKeepAliveMsg creates a new request to keep a session.
func NewSessionKeepAliveMsg() *SessionKeepAliveMsg {
	m := &SessionKeepAliveMsg{
		MsgHeader: MsgHeader{8, enums.MSG_TRANSPORT_SESSION_KEEPALIVE},
		Nonce:     util.RndUInt32(),
	}
	return m
}

// String returns a human-readable representation of the message.
func (m *SessionKeepAliveMsg) String() string {
	return fmt.Sprintf("SessionKeepAliveMsg{%d}", m.Nonce)
}

// Init called after unmarshalling a message to setup internal state
func (m *SessionKeepAliveMsg) Init() error { return nil }

//----------------------------------------------------------------------
// TRANSPORT_SESSION_KEEPALIVE_RESPONSE
//----------------------------------------------------------------------

// SessionKeepAliveRespMsg is a response for a peer to a "keep-alive" request.
type SessionKeepAliveRespMsg struct {
	MsgHeader
	Nonce uint32
}

// NewSessionKeepAliveRespMsg is a response message for a "keep session" request.
func NewSessionKeepAliveRespMsg(nonce uint32) *SessionKeepAliveRespMsg {
	m := &SessionKeepAliveRespMsg{
		MsgHeader: MsgHeader{8, enums.MSG_TRANSPORT_SESSION_KEEPALIVE_RESPONSE},
		Nonce:     nonce,
	}
	return m
}

// String returns a human-readable representation of the message.
func (m *SessionKeepAliveRespMsg) String() string {
	return fmt.Sprintf("SessionKeepAliveRespMsg{%d}", m.Nonce)
}

// Init called after unmarshalling a message to setup internal state
func (m *SessionKeepAliveRespMsg) Init() error { return nil }
