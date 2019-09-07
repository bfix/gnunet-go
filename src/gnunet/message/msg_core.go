package message

import (
	//"encoding/hex"
	"fmt"
	"time"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"gnunet/enums"
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
			SigPurpose:   enums.SIG_ECC_KEY,
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

// Header returns the message header in a separate instance.
func (msg *EphemeralKeyMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

func (m *EphemeralKeyMsg) Public() *ed25519.PublicKey {
	return ed25519.NewPublicKeyFromBytes(m.SignedBlock.PeerID)
}

func (m *EphemeralKeyMsg) Verify(pub *ed25519.PublicKey) (bool, error) {
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

func NewEphemeralKey(peerId []byte, ltPrv *ed25519.PrivateKey) (*ed25519.PrivateKey, *EphemeralKeyMsg, error) {
	msg := NewEphemeralKeyMsg()
	copy(msg.SignedBlock.PeerID, peerId)
	seed := util.NewRndArray(32)
	prv := ed25519.NewPrivateKeyFromSeed(seed)
	copy(msg.SignedBlock.EphemeralKey, prv.Public().Bytes())

	data, err := data.Marshal(msg.SignedBlock)
	if err != nil {
		return nil, nil, err
	}
	sig, err := ltPrv.EdSign(data)
	if err != nil {
		return nil, nil, err
	}
	copy(msg.Signature, sig.Bytes())

	return prv, msg, nil
}
