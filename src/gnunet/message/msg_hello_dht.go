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
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"gnunet/enums"
	"gnunet/util"
	"time"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// HELLO-DHT
//
// A HELLO message is used to exchange information about transports with
// other DHT nodes. This struct is always followed by the actual network
// addresses of type "HelloAddress"
//----------------------------------------------------------------------

// HelloDHTMsg is a message send by peers to announce their presence
type HelloDHTMsg struct {
	MsgSize   uint16            `order:"big"` // total size of message
	MsgType   uint16            `order:"big"` // DHT_P2P_HELLO (157)
	Reserved  uint16            `order:"big"` // Reserved for further use
	NumAddr   uint16            `order:"big"` // Number of addresses in list
	Signature []byte            `size:"64"`   // Signature
	Expires   util.AbsoluteTime ``            // expiration time
	AddrList  []byte            `size:"*"`    // List of end-point addresses (HelloAddress)
}

// NewHelloMsgDHT creates an empty DHT_P2P_HELLO message.
func NewHelloDHTMsg() *HelloDHTMsg {
	// return empty HelloMessage
	exp := time.Now().Add(HelloAddressExpiration)
	return &HelloDHTMsg{
		MsgSize:   80,                        // size without 'AddrList'
		MsgType:   DHT_P2P_HELLO,             // DHT_P2P_HELLO (157)
		Reserved:  0,                         // not used here
		NumAddr:   0,                         // start with empty address list
		Signature: make([]byte, 64),          // signature
		Expires:   util.NewAbsoluteTime(exp), // default expiration
		AddrList:  make([]byte, 0),           // list of addresses
	}
}

// Addresses returns the list of HelloAddress
func (m *HelloDHTMsg) Addresses() (list []*util.Address, err error) {
	var addr *util.Address
	var as string
	num, pos := 0, 0
	for {
		// parse address string from stream
		if as, pos = util.ReadCString(m.AddrList, pos); pos == -1 {
			break
		}
		if addr, err = util.ParseAddress(as); err != nil {
			return
		}
		addr.Expires = m.Expires
		list = append(list, addr)
		num++
	}
	// check numbers
	if num != int(m.NumAddr) {
		logger.Printf(logger.WARN, "[HelloDHTMsg] Number of addresses does not match (got %d, expected %d)", num, m.NumAddr)
	}
	return
}

// SetAddresses adds addresses to the HELLO message.
func (m *HelloDHTMsg) SetAddresses(list []*util.Address) {
	// write addresses as blob and track earliest expiration
	exp := util.NewAbsoluteTime(time.Now().Add(HelloAddressExpiration))
	wrt := new(bytes.Buffer)
	for _, addr := range list {
		// check if address expires before current expire
		if exp.Compare(addr.Expires) > 0 {
			exp = addr.Expires
		}
		n, _ := wrt.Write([]byte(addr.URI()))
		wrt.WriteByte(0)
		m.MsgSize += uint16(n + 1)
	}
	m.AddrList = wrt.Bytes()
	m.Expires = exp
	m.NumAddr = uint16(len(list))
}

// String returns a human-readable representation of the message.
func (m *HelloDHTMsg) String() string {
	addrs, _ := m.Addresses()
	aList := ""
	for i, a := range addrs {
		if i > 0 {
			aList += ","
		}
		aList += a.URI()
	}
	return fmt.Sprintf("HelloDHTMsg{expire:%s,addrs=%d:[%s]}", m.Expires, m.NumAddr, aList)
}

// Header returns the message header in a separate instance.
func (m *HelloDHTMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

// Verify the message signature
func (m *HelloDHTMsg) Verify(peer *util.PeerID) (bool, error) {
	// assemble signed data and public key
	sd := m.signedData()
	pub := peer.PublicKey()
	sig, err := ed25519.NewEdSignatureFromBytes(m.Signature)
	if err != nil {
		return false, err
	}
	return pub.EdVerify(sd, sig)
}

// Sign the HELLO data with private key
func (m *HelloDHTMsg) Sign(prv *ed25519.PrivateKey) error {
	// assemble signed data
	sd := m.signedData()
	sig, err := prv.EdSign(sd)
	if err != nil {
		return err
	}
	m.Signature = sig.Bytes()
	return nil
}

// signedData assembles a data block for sign and verify operations.
func (m *HelloDHTMsg) signedData() []byte {
	// hash address block
	hAddr := sha512.Sum512(m.AddrList)
	var size uint32 = 80
	purpose := uint32(enums.SIG_HELLO)

	// assemble signed data
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, size)
	binary.Write(buf, binary.BigEndian, purpose)
	binary.Write(buf, binary.BigEndian, m.Expires.Epoch()*1000000)
	buf.Write(hAddr[:])
	return buf.Bytes()
}
