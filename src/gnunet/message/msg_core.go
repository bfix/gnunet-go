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
	SignSize     uint32            `order:"big"` // length of signed block
	SigPurpose   uint32            `order:"big"` // signature purpose: SIG_ECC_KEY
	CreateTime   util.AbsoluteTime // Time of key creation
	ExpireTime   util.RelativeTime // Time to live for key
	EphemeralKey []byte            `size:"32"` // Ephemeral EdDSA public key
	PeerID       *util.PeerID      // Peer identity (EdDSA public key)
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
			CreateTime:   util.AbsoluteTimeNow(),
			ExpireTime:   util.NewRelativeTime(12 * time.Hour),
			EphemeralKey: make([]byte, 32),
			PeerID:       util.NewPeerID(nil),
		},
	}
}

func (m *EphemeralKeyMsg) String() string {
	return fmt.Sprintf("EphKeyMsg{peer=%s,ephkey=%s,create=%s,expire=%s,status=%d}",
		util.EncodeBinaryToString(m.SignedBlock.PeerID.Key),
		util.EncodeBinaryToString(m.SignedBlock.EphemeralKey),
		m.SignedBlock.CreateTime, m.SignedBlock.ExpireTime,
		m.SenderStatus)
}

// Header returns the message header in a separate instance.
func (msg *EphemeralKeyMsg) Header() *MessageHeader {
	return &MessageHeader{msg.MsgSize, msg.MsgType}
}

func (m *EphemeralKeyMsg) Public() *ed25519.PublicKey {
	return ed25519.NewPublicKeyFromBytes(m.SignedBlock.PeerID.Key)
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
	copy(msg.SignedBlock.PeerID.Key, peerId)
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
