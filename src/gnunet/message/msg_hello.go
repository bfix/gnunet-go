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
	"bytes"
	"encoding/binary"
	"fmt"
	"gnunet/util"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bfix/gospel/crypto/ed25519"
)

//----------------------------------------------------------------------
// HELLO URLs are used for bootstrapping a node and for adding nodes
// outside of GNUnet message exchange (e.g. command-line tools)
//----------------------------------------------------------------------

const helloPrefix = "gnunet://hello/"

// HelloData is the information used to create and parse HELLO URLs.
// All addresses expire at the same time /this different from HELLO
// messages (see below).
type HelloData struct {
	PeerID    *util.PeerID         // peer identifier
	Signature *ed25519.EdSignature // signature
	Expire    uint64               // expiration timestamp (Unix epoch)
	Addrs     []*util.Address      // list of addresses for peer
}

// ParseHelloURL parses a HELLO URL of the following form:
//     gnunet://hello/<PeerID>/<signature>/<expire>?<addrs>
// The addresses are encoded.
func ParseHelloURL(u string) (h *HelloData, err error) {
	// check and trim prefix
	if !strings.HasPrefix(u, helloPrefix) {
		err = fmt.Errorf("invalid HELLO-URL prefix: '%s'", u)
		return
	}
	u = u[len(helloPrefix):]

	// split remainder into parts
	p := strings.Split(u, "/")
	if len(p) != 3 {
		err = fmt.Errorf("invalid HELLO-URL: '%s'", u)
		return
	}

	// assemble HELLO data
	h = new(HelloData)

	// (1) parse peer public key (peer ID)
	var buf []byte
	if buf, err = util.DecodeStringToBinary(p[0], 32); err != nil {
		return
	}
	h.PeerID = util.NewPeerID(buf)

	// (2) parse signature
	if buf, err = util.DecodeStringToBinary(p[1], 64); err != nil {
		return
	}
	if h.Signature, err = ed25519.NewEdSignatureFromBytes(buf); err != nil {
		return
	}

	// (3) split last element into parts
	q := strings.SplitN(p[2], "?", 2)

	// (4) parse expiration date
	if h.Expire, err = strconv.ParseUint(q[0], 10, 64); err != nil {
		return
	}

	// (5) process addresses.
	h.Addrs = make([]*util.Address, 0)
	var ua string
	for _, a := range strings.Split(q[1], "&") {
		// unescape URL query
		if ua, err = url.QueryUnescape(a); err != nil {
			return
		}
		// parse address and append it to list
		var addr *util.Address
		if addr, err = util.ParseAddress(ua); err != nil {
			return
		}
		h.Addrs = append(h.Addrs, addr)
	}
	return
}

// URL returns the HELLO URL for the data.
func (h *HelloData) URL() string {
	u := fmt.Sprintf("%s%s/%s/%d?",
		helloPrefix,
		h.PeerID.String(),
		util.EncodeBinaryToString(h.Signature.Bytes()),
		h.Expire,
	)
	for i, a := range h.Addrs {
		if i > 0 {
			u += "&"
		}
		u += url.QueryEscape(a.String())
	}
	return u
}

// Equals returns true if two HELLOs are the same
func (h *HelloData) Equals(g *HelloData) bool {
	if !h.PeerID.Equals(g.PeerID) ||
		!util.Equals(h.Signature.Bytes(), g.Signature.Bytes()) ||
		h.Expire != g.Expire ||
		len(h.Addrs) != len(g.Addrs) {
		return false
	}
	for i, a := range h.Addrs {
		if !a.Equals(g.Addrs[i]) {
			return false
		}
	}
	return true
}

// Verify the integrity of the HELLO data
func (h *HelloData) Verify() (bool, error) {
	// assemble signed data and public key
	sd := h.signedData()
	pub := ed25519.NewPublicKeyFromBytes(h.PeerID.Key)
	return pub.EdVerify(sd, h.Signature)
}

// Sign the HELLO data with private key
func (h *HelloData) Sign(prv *ed25519.PrivateKey) (err error) {
	// assemble signed data
	sd := h.signedData()
	h.Signature, err = prv.EdSign(sd)
	return
}

// signedData assembles a data block for sign and verify operations.
func (h *HelloData) signedData() []byte {
	buf := new(bytes.Buffer)
	buf.Write(h.PeerID.Key)
	binary.Write(buf, binary.BigEndian, h.Expire)
	for _, a := range h.Addrs {
		buf.Write(a.Address)
	}
	return buf.Bytes()
}

//----------------------------------------------------------------------
// HELLO
//
// A HELLO message is used to exchange information about transports with
// other peers. This struct is always followed by the actual network
// addresses which have the format:
//
// 1) transport-name (0-terminated)
// 2) address-length (uint16_t, network byte order)
// 3) address expiration
// 4) address (address-length bytes)
//----------------------------------------------------------------------

// HelloAddress represents a (generic) peer address with expiration date
type HelloAddress struct {
	Transport string            // Name of transport
	AddrSize  uint16            `order:"big"` // Size of address entry
	ExpireOn  util.AbsoluteTime // Expiry date
	Address   []byte            `size:"AddrSize"` // Address specification
}

// NewHelloAddress create a new HELLO address from the given address
func NewHelloAddress(a *util.Address) *HelloAddress {
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

// HelloMsg is a message send by peers to announce their presence
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
func (m *HelloMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}
