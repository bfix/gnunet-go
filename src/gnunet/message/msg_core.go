package message

import (
	//"encoding/hex"
	"fmt"
	"time"

	"gnunet/crypto"
	"gnunet/util"
)

type EphKeyBlock struct {
	SignSize     uint32 `order:"big"` // length of signed block
	SigPurpose   uint32 `order:"big"` // signature purpose: SIG_ECC_KEY
	CreateTime   uint64 `order:"big"` // Time of key creation
	ExpireTime   uint64 `order:"big"` // Time of key expiration
	EphemeralKey []byte `size:"32"`   // Ephemeral EdDSA public key
	PeerID       []byte `size:"32"`   // Peer identity (EdDSA public key)
}

type EphemeralKeyMsg struct {
	MsgSize      uint16 `order:"big"` // total size of message
	MsgType      uint16 `order:"big"` // CORE_EPHEMERAL_KEY (88)
	SenderStatus uint32 `order:"big"` // enum PeerStateMachine
	Signature    []byte `size:"64"`   // EdDSA signature
	SignedBlock  *EphKeyBlock
}

func NewEphemeralKeyMsg() *EphemeralKeyMsg {
	return &EphemeralKeyMsg{
		MsgSize:      160,
		MsgType:      CORE_EPHEMERAL_KEY,
		SenderStatus: 1,
		Signature:    make([]byte, 64),
		SignedBlock: &EphKeyBlock{
			SignSize:     88,
			SigPurpose:   crypto.SIG_ECC_KEY,
			CreateTime:   util.GetAbsoluteTimeNow(),
			ExpireTime:   util.GetAbsoluteTimeOffset(12 * time.Hour),
			EphemeralKey: make([]byte, 32),
			PeerID:       make([]byte, 32),
		},
	}
}

func (m *EphemeralKeyMsg) String() string {
	return fmt.Sprintf("EphKeyMsg{%s,%s,%s,%d}",
		util.EncodeBinaryToString(m.SignedBlock.PeerID),
		util.EncodeBinaryToString(m.SignedBlock.EphemeralKey),
		util.Timestamp(m.SignedBlock.ExpireTime),
		m.SenderStatus)
}

// Size returns the total number of bytes in a message.
func (msg *EphemeralKeyMsg) Size() uint16 {
	return msg.MsgSize
}

// Type returns the message type
func (msg *EphemeralKeyMsg) Type() uint16 {
	return msg.MsgType
}

func (m *EphemeralKeyMsg) Public() *crypto.PublicKey {
	return crypto.NewPublicKey(m.SignedBlock.PeerID)
}

func (m *EphemeralKeyMsg) Verify(pub *crypto.PublicKey) bool {
	data, err := Marshal(m.SignedBlock)
	if err != nil {
		fmt.Printf("Verify: %s\n", err)
		return false
	}
	sig := crypto.NewSignatureFromBytes(m.Signature)
	return pub.Verify(data, sig)
}

func NewEphemeralKey(peerId []byte, ltPrv *crypto.PrivateKey) (*crypto.PrivateKey, *EphemeralKeyMsg, error) {
	msg := NewEphemeralKeyMsg()
	copy(msg.SignedBlock.PeerID, peerId)
	seed := util.NewRndArray(32)
	prv := crypto.PrivateKeyFromSeed(seed)
	copy(msg.SignedBlock.EphemeralKey, prv.Public().Bytes())

	data, err := Marshal(msg.SignedBlock)
	if err != nil {
		return nil, nil, err
	}
	sig, err := ltPrv.Sign(data)
	if err != nil {
		return nil, nil, err
	}
	copy(msg.Signature, sig.Bytes())

	return prv, msg, nil
}
