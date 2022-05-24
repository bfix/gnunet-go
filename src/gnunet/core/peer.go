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

package core

import (
	"fmt"

	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
)

// Peer represents a node in the GNUnet P2P network.
type Peer struct {
	prv      *ed25519.PrivateKey      // node private key (long-term signing key)
	pub      *ed25519.PublicKey       // node public key (=identifier)
	idString string                   // node identifier as string
	addrList []*util.Address          // list of addresses associated with node
	ephPrv   *ed25519.PrivateKey      // ephemeral signing key
	ephMsg   *message.EphemeralKeyMsg // ephemeral signing key message
}

// NewPeer instantiates a new peer object from given data. If a local peer
// is created, the data is the seed for generating the private key of the node;
// for a remote peer the data is the binary representation of its public key.
func NewPeer(data []byte, local bool) (p *Peer, err error) {
	p = new(Peer)
	if local {
		p.prv = ed25519.NewPrivateKeyFromSeed(data)
		p.pub = p.prv.Public()
		p.ephPrv, p.ephMsg, err = message.NewEphemeralKey(p.pub.Bytes(), p.prv)
		if err != nil {
			return
		}
	} else {
		p.prv = nil
		p.pub = ed25519.NewPublicKeyFromBytes(data)
	}
	p.idString = util.EncodeBinaryToString(p.pub.Bytes())
	p.addrList = make([]*util.Address, 0)
	return
}

// EphKeyMsg returns a new initialized message to negotiate session keys.
func (p *Peer) EphKeyMsg() *message.EphemeralKeyMsg {
	return p.ephMsg
}

// SetEphKeyMsg saves a template for new key negotiation messages.
func (p *Peer) SetEphKeyMsg(msg *message.EphemeralKeyMsg) {
	p.ephMsg = msg
}

// EphPrvKey returns the current ephemeral private key.
func (p *Peer) EphPrvKey() *ed25519.PrivateKey {
	return p.ephPrv
}

// PrvKey return the private key of the node.
func (p *Peer) PrvKey() *ed25519.PrivateKey {
	return p.prv
}

// PubKey return the public key of the node.
func (p *Peer) PubKey() *ed25519.PublicKey {
	return p.pub
}

// GetID returns the node ID (public key) in binary format
func (p *Peer) GetID() util.PeerID {
	var id util.PeerID
	copy(id.Key, p.pub.Bytes())
	return id
}

// GetIDString returns the string representation of the public key of the node.
func (p *Peer) GetIDString() string {
	return p.idString
}

// GetAddressList returns a list of addresses associated with this peer.
func (p *Peer) GetAddressList() []*util.Address {
	return p.addrList
}

// AddAddress adds a new address for a node.
func (p *Peer) AddAddress(a *util.Address) {
	p.addrList = append(p.addrList, a)
}

// Sign a message with the (long-term) private key.
func (p *Peer) Sign(msg []byte) (*ed25519.EdSignature, error) {
	if p.prv == nil {
		return nil, fmt.Errorf("No private key")
	}
	return p.prv.EdSign(msg)
}

// Verify a message signature with the public key of a peer.
func (p *Peer) Verify(msg []byte, sig *ed25519.EdSignature) (bool, error) {
	return p.pub.EdVerify(msg, sig)
}
