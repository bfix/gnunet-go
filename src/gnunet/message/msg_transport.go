package message

import (
	"fmt"
	"time"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
)

//----------------------------------------------------------------------
// TRANSPORT_TCP_WELCOME
//----------------------------------------------------------------------

// TransportTcpWelcomeMsg
type TransportTcpWelcomeMsg struct {
	MsgSize uint16       `order:"big"` // total size of message
	MsgType uint16       `order:"big"` // TRANSPORT_TCP_WELCOME (61)
	PeerID  *util.PeerID // Peer identity (EdDSA public key)
}

// NewTransportTcpWelcomeMsg creates a new message for a given peer.
func NewTransportTcpWelcomeMsg(peerid *util.PeerID) *TransportTcpWelcomeMsg {
	if peerid == nil {
		peerid = util.NewPeerID(nil)
	}
	return &TransportTcpWelcomeMsg{
		MsgSize: 36,
		MsgType: TRANSPORT_TCP_WELCOME,
		PeerID:  peerid,
	}
}

// String returns a human-readable representation of the message.
func (m *TransportTcpWelcomeMsg) String() string {
	return fmt.Sprintf("TransportTcpWelcomeMsg{peer=%s}", m.PeerID)
}

// Header returns the message header in a separate instance.
func (msg *TransportTcpWelcomeMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_PING
//
// Message used to ask a peer to validate receipt (to check an address
// from a HELLO).  Followed by the address we are trying to validate,
// or an empty address if we are just sending a PING to confirm that a
// connection which the receiver (of the PING) initiated is still valid.
//----------------------------------------------------------------------

// TransportPingMsg
type TransportPingMsg struct {
	MsgSize   uint16       `order:"big"` // total size of message
	MsgType   uint16       `order:"big"` // TRANSPORT_PING (372)
	Challenge uint32       // Challenge code (to ensure fresh reply)
	Target    *util.PeerID // EdDSA public key (long-term) of target peer
	Address   []byte       `size:"*"` // encoded address
}

// TransportPingMsg creates a new message for given peer with an address to
// be validated.
func NewTransportPingMsg(target *util.PeerID, a *util.Address) *TransportPingMsg {
	if target == nil {
		target = util.NewPeerID(nil)
	}
	m := &TransportPingMsg{
		MsgSize:   uint16(40),
		MsgType:   TRANSPORT_PING,
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
	data.Unmarshal(a, m.Address)
	return fmt.Sprintf("TransportPingMsg{target=%s,addr=%s,challenge=%d}",
		m.Target, a, m.Challenge)
}

// Header returns the message header in a separate instance.
func (msg *TransportPingMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

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

// TransportPongMsg
type TransportPongMsg struct {
	MsgSize     uint16         `order:"big"` // total size of message
	MsgType     uint16         `order:"big"` // TRANSPORT_PING (372)
	Challenge   uint32         // Challenge code (to ensure fresh reply)
	Signature   []byte         `size:"64"` // Signature of address
	SignedBlock *SignedAddress // signed block of data
}

// NewTransportPongMsg creates a reponse message with an address the replying
// peer wants to be reached.
func NewTransportPongMsg(challenge uint32, a *util.Address) *TransportPongMsg {
	m := &TransportPongMsg{
		MsgSize:     72,
		MsgType:     TRANSPORT_PONG,
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
	return fmt.Sprintf("TransportPongMsg{addr=<unkown>,%d}", m.Challenge)
}

// Header returns the message header in a separate instance.
func (msg *TransportPongMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
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

//----------------------------------------------------------------------
// HELLO
//
// A HELLO message is used to exchange information about
// transports with other peers.  This struct is always
// followed by the actual network addresses which have
// the format:
//
// 1) transport-name (0-terminated)
// 2) address-length (uint16_t, network byte order)
// 3) address expiration
// 4) address (address-length bytes)
//----------------------------------------------------------------------

// HelloAddress
type HelloAddress struct {
	Transport string            // Name of transport
	AddrSize  uint16            `order:"big"` // Size of address entry
	ExpireOn  util.AbsoluteTime // Expiry date
	Address   []byte            `size:"AddrSize"` // Address specification
}

// NewHelloAddress create a new HELLO address from the given address
func NewAddress(a *util.Address) *HelloAddress {
	addr := &HelloAddress{
		Transport: a.Transport,
		AddrSize:  uint16(len(a.Address)),
		ExpireOn:  util.AbsoluteTimeNow().Add(12 * time.Hour),
		Address:   make([]byte, len(a.Address)),
	}
	copy(addr.Address, a.Address)
	return addr
}

// String returns a human-readable representation of the message.
func (a *HelloAddress) String() string {
	return fmt.Sprintf("Address{%s,expire=%s}",
		util.AddressString(a.Transport, a.Address), a.ExpireOn)
}

// HelloMsg
type HelloMsg struct {
	MsgSize    uint16          `order:"big"` // total size of message
	MsgType    uint16          `order:"big"` // HELLO (17)
	FriendOnly uint32          `order:"big"` // =1: do not gossip this HELLO
	PeerID     *util.PeerID    // EdDSA public key (long-term)
	Addresses  []*HelloAddress `size:"*"` // List of end-point addressess
}

// NewHelloMsg creates a new HELLO msg for a given peer.
func NewHelloMsg(peerid *util.PeerID) *HelloMsg {
	if peerid == nil {
		peerid = util.NewPeerID(nil)
	}
	return &HelloMsg{
		MsgSize:    40,
		MsgType:    HELLO,
		FriendOnly: 0,
		PeerID:     peerid,
		Addresses:  make([]*HelloAddress, 0),
	}
}

// String returns a human-readable representation of the message.
func (m *HelloMsg) String() string {
	return fmt.Sprintf("HelloMsg{peer=%s,friendsonly=%d,addr=%v}",
		m.PeerID, m.FriendOnly, m.Addresses)
}

// AddAddress adds a new address to the HELLO message.
func (m *HelloMsg) AddAddress(a *HelloAddress) {
	m.Addresses = append(m.Addresses, a)
	m.MsgSize += uint16(len(a.Transport)) + a.AddrSize + 11
}

// Header returns the message header in a separate instance.
func (msg *HelloMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_SESSION_ACK
//----------------------------------------------------------------------

// SessionAckMsg
type SessionAckMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // TRANSPORT_SESSION_ACK (377)
}

// NewSessionAckMsg creates an new message (no body required).
func NewSessionAckMsg() *SessionAckMsg {
	return &SessionAckMsg{
		MsgSize: 16,
		MsgType: TRANSPORT_SESSION_ACK,
	}
}

// String returns a human-readable representation of the message.
func (m *SessionAckMsg) String() string {
	return "SessionAck{}"
}

// Header returns the message header in a separate instance.
func (msg *SessionAckMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_SESSION_SYN
//----------------------------------------------------------------------

// SessionSynMsg
type SessionSynMsg struct {
	MsgSize   uint16            `order:"big"` // total size of message
	MsgType   uint16            `order:"big"` // TRANSPORT_SESSION_SYN (375)
	Reserved  uint32            `order:"big"` // reserved (=0)
	Timestamp util.AbsoluteTime // usec epoch
}

// NewSessionSynMsg creates a SYN request for the a session
func NewSessionSynMsg() *SessionSynMsg {
	return &SessionSynMsg{
		MsgSize:   16,
		MsgType:   TRANSPORT_SESSION_SYN,
		Reserved:  0,
		Timestamp: util.AbsoluteTimeNow(),
	}
}

// String returns a human-readable representation of the message.
func (m *SessionSynMsg) String() string {
	return fmt.Sprintf("SessionSyn{timestamp=%s}", m.Timestamp)
}

// Header returns the message header in a separate instance.
func (msg *SessionSynMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_SESSION_SYN_ACK
//----------------------------------------------------------------------

// SessionSynAckMsg
type SessionSynAckMsg struct {
	MsgSize   uint16            `order:"big"` // total size of message
	MsgType   uint16            `order:"big"` // TRANSPORT_SESSION_SYN_ACK (376)
	Reserved  uint32            `order:"big"` // reserved (=0)
	Timestamp util.AbsoluteTime // usec epoch
}

// NewSessionSynAckMsg is an ACK for a SYN request
func NewSessionSynAckMsg() *SessionSynAckMsg {
	return &SessionSynAckMsg{
		MsgSize:   16,
		MsgType:   TRANSPORT_SESSION_SYN_ACK,
		Reserved:  0,
		Timestamp: util.AbsoluteTimeNow(),
	}
}

// String returns a human-readable representation of the message.
func (m *SessionSynAckMsg) String() string {
	return fmt.Sprintf("SessionSynAck{timestamp=%s}", m.Timestamp)
}

// Header returns the message header in a separate instance.
func (msg *SessionSynAckMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_SESSION_QUOTA
//----------------------------------------------------------------------

// SessionQuotaMsg
type SessionQuotaMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // TRANSPORT_SESSION_QUOTA (379)
	Quota   uint32 `order:"big"` // Quota in bytes per second
}

// NewSessionQuotaMsg announces a session quota to the other end of the session.
func NewSessionQuotaMsg(quota uint32) *SessionQuotaMsg {
	m := new(SessionQuotaMsg)
	if quota > 0 {
		m.MsgSize = 8
		m.MsgType = TRANSPORT_SESSION_QUOTA
		m.Quota = quota
	}
	return m
}

// String returns a human-readable representation of the message.
func (m *SessionQuotaMsg) String() string {
	return fmt.Sprintf("SessionQuotaMsg{%sB/s}", util.Scale1024(uint64(m.Quota)))
}

// Header returns the message header in a separate instance.
func (msg *SessionQuotaMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_SESSION_KEEPALIVE
//----------------------------------------------------------------------

// SessionKeepAliveMsg
type SessionKeepAliveMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // TRANSPORT_SESSION_KEEPALIVE (381)
	Nonce   uint32
}

// NewSessionKeepAliveMsg creates a new request to keep a session.
func NewSessionKeepAliveMsg() *SessionKeepAliveMsg {
	m := &SessionKeepAliveMsg{
		MsgSize: 8,
		MsgType: TRANSPORT_SESSION_KEEPALIVE,
		Nonce:   util.RndUInt32(),
	}
	return m
}

// String returns a human-readable representation of the message.
func (m *SessionKeepAliveMsg) String() string {
	return fmt.Sprintf("SessionKeepAliveMsg{%d}", m.Nonce)
}

// Header returns the message header in a separate instance.
func (msg *SessionKeepAliveMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_SESSION_KEEPALIVE_RESPONSE
//----------------------------------------------------------------------

// SessionKeepAliveRespMsg
type SessionKeepAliveRespMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // TRANSPORT_SESSION_KEEPALIVE_RESPONSE (382)
	Nonce   uint32
}

// NewSessionKeepAliveRespMsg is a response message for a "keep session" request.
func NewSessionKeepAliveRespMsg(nonce uint32) *SessionKeepAliveRespMsg {
	m := &SessionKeepAliveRespMsg{
		MsgSize: 8,
		MsgType: TRANSPORT_SESSION_KEEPALIVE_RESPONSE,
		Nonce:   nonce,
	}
	return m
}

// String returns a human-readable representation of the message.
func (m *SessionKeepAliveRespMsg) String() string {
	return fmt.Sprintf("SessionKeepAliveRespMsg{%d}", m.Nonce)
}

// Header returns the message header in a separate instance.
func (msg *SessionKeepAliveRespMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}
