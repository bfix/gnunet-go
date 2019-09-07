package message

import (
	"fmt"
	"time"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"gnunet/enums"
	"gnunet/util"
)

//----------------------------------------------------------------------
// TRANSPORT_TCP_WELCOME
//----------------------------------------------------------------------

type TransportTcpWelcomeMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // TRANSPORT_TCP_WELCOME (61)
	PeerID  []byte `size:"32"`   // Peer identity (EdDSA public key)
}

func NewTransportTcpWelcomeMsg(peerid []byte) *TransportTcpWelcomeMsg {
	msg := &TransportTcpWelcomeMsg{
		MsgSize: 36,
		MsgType: TRANSPORT_TCP_WELCOME,
		PeerID:  make([]byte, 32),
	}
	if peerid != nil {
		copy(msg.PeerID[:], peerid)
	} else {
		msg.MsgSize = 0
		msg.MsgType = 0
	}
	return msg
}

func (m *TransportTcpWelcomeMsg) String() string {
	return fmt.Sprintf("TransportTcpWelcomeMsg{'%s'}", util.EncodeBinaryToString(m.PeerID))
}

// Header returns the message header in a separate instance.
func (msg *TransportTcpWelcomeMsg) Header() *MessageHeader {
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

type SignedAddress struct {
	SignLength uint32 `order:"big"`     // Length of signed block
	Purpose    uint32 `order:"big"`     // SIG_TRANSPORT_PONG_OWN
	ExpireOn   uint64 `order:"big"`     // usec epoch
	AddrSize   uint32 `order:"big"`     // size of address
	Address    []byte `size:"AddrSize"` // address
}

func NewSignedAddress(a *util.Address) *SignedAddress {
	// serialize address
	addrData, _ := data.Marshal(a)
	alen := len(addrData)
	addr := &SignedAddress{
		SignLength: uint32(alen + 20),
		Purpose:    enums.SIG_TRANSPORT_PONG_OWN,
		ExpireOn:   util.GetAbsoluteTimeOffset(12 * time.Hour),
		AddrSize:   uint32(alen),
		Address:    make([]byte, alen),
	}
	copy(addr.Address, addrData)
	return addr
}

type TransportPongMsg struct {
	MsgSize     uint16         `order:"big"` // total size of message
	MsgType     uint16         `order:"big"` // TRANSPORT_PING (372)
	Challenge   uint32         // Challenge code (to ensure fresh reply)
	Signature   []byte         `size:"64"` // Signature of address
	SignedBlock *SignedAddress // signed block of data
}

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
		m.MsgSize += uint16(sa.SignLength)
		m.SignedBlock = sa
	}
	return m
}

func (m *TransportPongMsg) String() string {
	a := new(util.Address)
	if err := data.Unmarshal(a, m.SignedBlock.Address); err == nil {
		return fmt.Sprintf("TransportPongMsg{%s,%d}", a, m.Challenge)
	}
	return fmt.Sprintf("TransportPongMsg{<unkown>,%d}", m.Challenge)
}

// Header returns the message header in a separate instance.
func (msg *TransportPongMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

func (m *TransportPongMsg) Sign(prv *ed25519.PrivateKey) error {
	data, err := data.Marshal(m.SignedBlock)
	if err != nil {
		fmt.Printf("Sign: %s\n", err)
		return err
	}
	sig, err := prv.EdSign(data)
	if err != nil {
		fmt.Printf("Sign: %s\n", err)
		return err
	}
	copy(m.Signature, sig.Bytes())
	return nil
}

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
// TRANSPORT_PING
//
// Message used to ask a peer to validate receipt (to check an address
// from a HELLO).  Followed by the address we are trying to validate,
// or an empty address if we are just sending a PING to confirm that a
// connection which the receiver (of the PING) initiated is still valid.
//----------------------------------------------------------------------

type TransportPingMsg struct {
	MsgSize   uint16 `order:"big"` // total size of message
	MsgType   uint16 `order:"big"` // TRANSPORT_PING (372)
	Challenge uint32 // Challenge code (to ensure fresh reply)
	Target    []byte `size:"32"` // EdDSA public key (long-term) of target peer
	Address   []byte `size:"*"`  // encoded address
}

func NewTransportPingMsg(target []byte, a *util.Address) *TransportPingMsg {
	m := &TransportPingMsg{
		MsgSize:   uint16(40),
		MsgType:   TRANSPORT_PING,
		Challenge: util.RndUInt32(),
		Target:    make([]byte, 32),
		Address:   nil,
	}
	if target != nil {
		copy(m.Target, target)
	}
	if a != nil {
		if addrData, err := data.Marshal(a); err == nil {
			m.Address = addrData
			m.MsgSize += uint16(len(addrData))
		}
	}
	return m
}

func (m *TransportPingMsg) String() string {
	a := new(util.Address)
	data.Unmarshal(a, m.Address)
	return fmt.Sprintf("TransportPingMsg{%s,%s,%d}",
		util.EncodeBinaryToString(m.Target), a, m.Challenge)
}

// Header returns the message header in a separate instance.
func (msg *TransportPingMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
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

type HelloAddress struct {
	Transport string // Name of transport
	AddrSize  uint16 `order:"big"`     // Size of address entry
	ExpireOn  uint64 `order:"big"`     // Expiry date
	Address   []byte `size:"AddrSize"` // Address specification
}

func NewAddress(a *util.Address) *HelloAddress {
	addr := &HelloAddress{
		Transport: a.Transport,
		AddrSize:  uint16(len(a.Address)),
		ExpireOn:  util.GetAbsoluteTimeOffset(12 * time.Hour),
		Address:   make([]byte, len(a.Address)),
	}
	copy(addr.Address, a.Address)
	return addr
}

func (a *HelloAddress) String() string {
	return fmt.Sprintf("Address{%s,%s}", util.AddressString(a.Transport, a.Address), util.Timestamp(a.ExpireOn))
}

type HelloMsg struct {
	MsgSize    uint16          `order:"big"` // total size of message
	MsgType    uint16          `order:"big"` // HELLO (17)
	FriendOnly uint32          `order:"big"` // =1: do not gossip this HELLO
	PeerID     []byte          `size:"32"`   // EdDSA public key (long-term)
	Addresses  []*HelloAddress `size:"*"`    // List of end-point addressess
}

func NewHelloMsg(peerid []byte) *HelloMsg {
	m := &HelloMsg{
		MsgSize:    40,
		MsgType:    HELLO,
		FriendOnly: 0,
		PeerID:     make([]byte, 32),
		Addresses:  make([]*HelloAddress, 0),
	}
	if peerid != nil {
		copy(m.PeerID, peerid)
	}
	return m
}

func (m *HelloMsg) String() string {
	return fmt.Sprintf("HelloMsg{%s,%d,%v}", util.EncodeBinaryToString(m.PeerID), m.FriendOnly, m.Addresses)
}

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

type SessionAckMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // TRANSPORT_SESSION_ACK (377)
}

func NewSessionAckMsg() *SessionAckMsg {
	return &SessionAckMsg{
		MsgSize: 16,
		MsgType: TRANSPORT_SESSION_ACK,
	}
}

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

type SessionSynMsg struct {
	MsgSize   uint16 `order:"big"` // total size of message
	MsgType   uint16 `order:"big"` // TRANSPORT_SESSION_SYN (375)
	Reserved  uint32 `order:"big"` // reserved (=0)
	Timestamp uint64 `order:"big"` // usec epoch
}

func NewSessionSynMsg(t uint64) *SessionSynMsg {
	if t == 0 {
		t = util.GetAbsoluteTimeNow()
	}
	return &SessionSynMsg{
		MsgSize:   16,
		MsgType:   TRANSPORT_SESSION_SYN,
		Reserved:  0,
		Timestamp: t,
	}
}

func (m *SessionSynMsg) String() string {
	return fmt.Sprintf("SessionSyn{%s}", util.Timestamp(m.Timestamp))
}

// Header returns the message header in a separate instance.
func (msg *SessionSynMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_SESSION_SYN_ACK
//----------------------------------------------------------------------

type SessionSynAckMsg struct {
	MsgSize   uint16 `order:"big"` // total size of message
	MsgType   uint16 `order:"big"` // TRANSPORT_SESSION_SYN_ACK (376)
	Reserved  uint32 `order:"big"` // reserved (=0)
	Timestamp uint64 `order:"big"` // usec epoch
}

func NewSessionSynAckMsg(t uint64) *SessionSynAckMsg {
	if t == 0 {
		t = util.GetAbsoluteTimeNow()
	}
	return &SessionSynAckMsg{
		MsgSize:   16,
		MsgType:   TRANSPORT_SESSION_SYN_ACK,
		Reserved:  0,
		Timestamp: t,
	}
}

func (m *SessionSynAckMsg) String() string {
	return fmt.Sprintf("SessionSynAck{%s}", util.Timestamp(m.Timestamp))
}

// Header returns the message header in a separate instance.
func (msg *SessionSynAckMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_SESSION_QUOTA
//----------------------------------------------------------------------

type SessionQuotaMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // TRANSPORT_SESSION_QUOTA (379)
	Quota   uint32 `order:"big"` // Quota in bytes per second
}

func NewSessionQuotaMsg(quota uint32) *SessionQuotaMsg {
	m := new(SessionQuotaMsg)
	if quota > 0 {
		m.MsgSize = 8
		m.MsgType = TRANSPORT_SESSION_QUOTA
		m.Quota = quota
	}
	return m
}

func (m *SessionQuotaMsg) String() string {
	return fmt.Sprintf("SessionQuotaMsg{%sB/s}", util.Scale1024(uint64(m.Quota)))
}

// Header returns the message header in a separate instance.
func (msg *SessionQuotaMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_SESSION_KEEPALIVE_RESPONSE
//----------------------------------------------------------------------

type SessionKeepAliveRespMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // TRANSPORT_SESSION_KEEPALIVE_RESPONSE (382)
	Nonce   uint32
}

func NewSessionKeepAliveRespMsg(nonce uint32) *SessionKeepAliveRespMsg {
	m := &SessionKeepAliveRespMsg{
		MsgSize: 8,
		MsgType: TRANSPORT_SESSION_KEEPALIVE_RESPONSE,
		Nonce:   nonce,
	}
	return m
}

func (m *SessionKeepAliveRespMsg) String() string {
	return fmt.Sprintf("SessionKeepAliveRespMsg{%d}", m.Nonce)
}

// Header returns the message header in a separate instance.
func (msg *SessionKeepAliveRespMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

//----------------------------------------------------------------------
// TRANSPORT_SESSION_KEEPALIVE
//----------------------------------------------------------------------

type SessionKeepAliveMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // TRANSPORT_SESSION_KEEPALIVE (381)
	Nonce   uint32
}

func NewSessionKeepAliveMsg() *SessionKeepAliveMsg {
	m := &SessionKeepAliveMsg{
		MsgSize: 8,
		MsgType: TRANSPORT_SESSION_KEEPALIVE,
		Nonce:   util.RndUInt32(),
	}
	return m
}

func (m *SessionKeepAliveMsg) String() string {
	return fmt.Sprintf("SessionKeepAliveMsg{%d}", m.Nonce)
}

// Header returns the message header in a separate instance.
func (msg *SessionKeepAliveMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}
