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
	"encoding/base64"
	"fmt"
	"time"

	"gnunet/config"
	"gnunet/message"
	"gnunet/service/dht/blocks"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
)

//----------------------------------------------------------------------
// GNUnet P2P network node (local or remote):
//
// * A LOCAL node has a long-term EdDSA key pair used for signing. The
//   public key is the node identifier (PeerID).
//   Local nodes hold additional attributes like ephemeral keys for message
//   exchange or a list of network addresses the node can be reached on.
//
// * A REMOTE node only has a public EdDSA key used by the local node
//   to verify signatures from the remote node.
//----------------------------------------------------------------------

// Peer represents a node in the GNUnet P2P network.
type Peer struct {
	prv      *ed25519.PrivateKey      // node private key (long-term signing key)
	pub      *ed25519.PublicKey       // node public key (=identifier)
	idString string                   // node identifier as string
	addrList []*util.Address          // list of addresses associated with node
	ephPrv   *ed25519.PrivateKey      // ephemeral signing key
	ephMsg   *message.EphemeralKeyMsg // ephemeral signing key message
}

//----------------------------------------------------------------------
// Create new peer objects
//----------------------------------------------------------------------

// NewLocalPeer creates a new local node from configuration data.
func NewLocalPeer(cfg *config.NodeConfig) (p *Peer, err error) {
	p = new(Peer)

	// get the key material for local node
	var data []byte
	if data, err = base64.StdEncoding.DecodeString(cfg.PrivateSeed); err != nil {
		return
	}
	p.prv = ed25519.NewPrivateKeyFromSeed(data)
	p.pub = p.prv.Public()
	p.idString = util.EncodeBinaryToString(p.pub.Bytes())
	p.ephPrv, p.ephMsg, err = message.NewEphemeralKey(p.pub.Bytes(), p.prv)
	if err != nil {
		return
	}
	// set the endpoint addresses for local node
	p.addrList = make([]*util.Address, len(cfg.Endpoints))
	var addr *util.Address
	for i, a := range cfg.Endpoints {
		if addr, err = util.ParseAddress(a); err != nil {
			return
		}
		addr.Expires = util.NewAbsoluteTime(time.Now().Add(12 * time.Hour))
		p.addrList[i] = addr
	}
	return
}

// NewPeer instantiates a new (remote) peer object from given peer ID string.
func NewPeer(peerID string) (p *Peer, err error) {
	p = new(Peer)

	// get the key material for local node
	var data []byte
	if data, err = util.DecodeStringToBinary(peerID, 32); err != nil {
		return
	}
	p.prv = nil
	p.pub = ed25519.NewPublicKeyFromBytes(data)
	p.idString = util.EncodeBinaryToString(p.pub.Bytes())
	p.addrList = make([]*util.Address, 0)
	return
}

//----------------------------------------------------------------------
//----------------------------------------------------------------------

// Address returns a peer address for the given transport protocol
func (p *Peer) Address(transport string) *util.Address {
	for _, addr := range p.addrList {
		// skip expired entries
		if addr.Expires.Expired() {
			continue
		}
		// filter by transport protocol
		if len(transport) > 0 && transport != addr.Netw {
			continue
		}
		return addr
	}
	return nil
}

// HelloData returns the current HELLO data for the peer. The list of listening
// endpoint addresses re passed in from core to reflect the actual active
// endpoints.
func (p *Peer) HelloData(ttl time.Duration, a []*util.Address) (h *blocks.HelloBlock, err error) {
	// assemble HELLO data
	h = new(blocks.HelloBlock)
	h.PeerID = p.GetID()
	h.Expire = util.NewAbsoluteTime(time.Now().Add(ttl))
	h.SetAddresses(a)

	// sign data
	err = h.Sign(p.prv)
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
func (p *Peer) GetID() *util.PeerID {
	return &util.PeerID{
		Key: util.Clone(p.pub.Bytes()),
	}
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
