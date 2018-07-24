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
	b := &EphKeyBlock{
		SignSize:     88,
		SigPurpose:   crypto.SIG_ECC_KEY,
		CreateTime:   util.GetAbsoluteTimeNow(),
		ExpireTime:   util.GetAbsoluteTimeOffset(12 * time.Hour),
		EphemeralKey: make([]byte, 32),
		PeerID:       make([]byte, 32),
	}
	return &EphemeralKeyMsg{
		MsgSize:      160,
		MsgType:      CORE_EPHEMERAL_KEY,
		SenderStatus: 1,
		Signature:    make([]byte, 64),
		SignedBlock:  b,
	}
}

func (m *EphemeralKeyMsg) String() string {
	return fmt.Sprintf("EphKeyMsg{%s,%s,%s,%d}",
		util.EncodeBinaryToString(m.SignedBlock.PeerID),
		util.EncodeBinaryToString(m.SignedBlock.EphemeralKey),
		util.Timestamp(m.SignedBlock.ExpireTime),
		m.SenderStatus)
}

func (m *EphemeralKeyMsg) Public() *crypto.EdDSAPublicKey {
	return crypto.NewEdDSAPublicKey(m.SignedBlock.PeerID)
}

func (m *EphemeralKeyMsg) Verify(pub *crypto.EdDSAPublicKey) bool {
	data, err := Marshal(m.SignedBlock)
	if err != nil {
		fmt.Printf("Verify: %s\n", err)
		return false
	}
	return pub.Verify(data, m.Signature)
}

func NewEphemeralKey(peerId []byte, ltPrv *crypto.EdDSAPrivateKey) (*crypto.EdDSAPrivateKey, *EphemeralKeyMsg, error) {
	msg := NewEphemeralKeyMsg()
	copy(msg.SignedBlock.PeerID, peerId)
	seed := make([]byte, 32)
	util.RndArray(seed)
	prv := crypto.EdDSAPrivateKeyFromSeed(seed)
	copy(msg.SignedBlock.EphemeralKey, prv.Public().Bytes())

	data, err := Marshal(msg.SignedBlock)
	if err != nil {
		return nil, nil, err
	}
	sig, err := ltPrv.Sign(data)
	if err != nil {
		return nil, nil, err
	}
	msg.Signature = sig

	return prv, msg, nil
}
