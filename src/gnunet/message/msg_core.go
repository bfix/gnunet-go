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
	//"encoding/hex"
	"fmt"
	"time"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
)

// EphKeyBlock defines the layout of signed ephemeral key with attributes.
type EphKeyBlock struct {
	Purpose      *crypto.SignaturePurpose // signature purpose: SIG_ECC_KEY
	CreateTime   util.AbsoluteTime        // Time of key creation
	ExpireTime   util.RelativeTime        // Time to live for key
	EphemeralKey *util.PeerPublicKey      // Ephemeral EdDSA public key
	PeerID       *util.PeerID             // Peer identity (EdDSA public key)
}

// EphemeralKeyMsg announces a new transient key for a peer. The key is signed
// by the issuing peer.
type EphemeralKeyMsg struct {
	MsgHeader
	SenderStatus uint32              `order:"big"` // enum PeerStateMachine
	Signature    *util.PeerSignature ``            // EdDSA signature
	SignedBlock  *EphKeyBlock
}

// NewEphemeralKeyMsg creates an empty message for key announcement.
func NewEphemeralKeyMsg() *EphemeralKeyMsg {
	return &EphemeralKeyMsg{
		MsgHeader:    MsgHeader{160, enums.MSG_CORE_EPHEMERAL_KEY},
		SenderStatus: 1,
		Signature:    util.NewPeerSignature(nil),
		SignedBlock: &EphKeyBlock{
			Purpose: &crypto.SignaturePurpose{
				Size:    88,
				Purpose: enums.SIG_SET_ECC_KEY,
			},
			CreateTime:   util.AbsoluteTimeNow(),
			ExpireTime:   util.NewRelativeTime(12 * time.Hour),
			EphemeralKey: util.NewPeerPublicKey(nil),
			PeerID:       util.NewPeerID(nil),
		},
	}
}

// String returns a human-readable representation of the message.
func (m *EphemeralKeyMsg) String() string {
	return fmt.Sprintf("EphKeyMsg{peer=%s,ephkey=%s,create=%s,expire=%s,status=%d}",
		util.EncodeBinaryToString(m.SignedBlock.PeerID.Data),
		util.EncodeBinaryToString(m.SignedBlock.EphemeralKey.Data),
		m.SignedBlock.CreateTime, m.SignedBlock.ExpireTime,
		m.SenderStatus)
}

// Public extracts the public key of an announcing peer.
func (m *EphemeralKeyMsg) Public() *util.PeerPublicKey {
	return util.NewPeerPublicKey(m.SignedBlock.PeerID.Data)
}

// Verify the integrity of the message data using the public key of the
// announcing peer.
func (m *EphemeralKeyMsg) Verify(pub *ed25519.PublicKey) (bool, error) {
	data, err := data.Marshal(m.SignedBlock)
	if err != nil {
		return false, err
	}
	sig, err := ed25519.NewEdSignatureFromBytes(m.Signature.Data)
	if err != nil {
		return false, err
	}
	return pub.EdVerify(data, sig)
}

// NewEphemeralKey creates a new ephemeral key signed by a long-term private
// key and the corresponding GNUnet message to announce the new key.
func NewEphemeralKey(peerID []byte, ltPrv *ed25519.PrivateKey) (*ed25519.PrivateKey, *EphemeralKeyMsg, error) {
	msg := NewEphemeralKeyMsg()
	copy(msg.SignedBlock.PeerID.Data, peerID)
	seed := util.NewRndArray(32)
	prv := ed25519.NewPrivateKeyFromSeed(seed)
	copy(msg.SignedBlock.EphemeralKey.Data, prv.Public().Bytes())

	data, err := data.Marshal(msg.SignedBlock)
	if err != nil {
		return nil, nil, err
	}
	sig, err := ltPrv.EdSign(data)
	if err != nil {
		return nil, nil, err
	}
	copy(msg.Signature.Data, sig.Bytes())

	return prv, msg, nil
}
