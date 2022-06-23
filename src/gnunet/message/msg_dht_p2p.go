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
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/service/dht/filter"
	"gnunet/util"
	"time"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
)

//======================================================================
// DHT-P2P is a next-generation implementation of the R5N DHT.
//======================================================================

//----------------------------------------------------------------------
// DHT-P2P-GET messages are used to request information from other
// peers in the DHT.
//----------------------------------------------------------------------

// DHTP2PGetMsg wire layout
type DHTP2PGetMsg struct {
	MsgSize   uint16              `order:"big"`   // total size of message
	MsgType   uint16              `order:"big"`   // DHT_P2P_GET (147)
	BType     uint32              `order:"big"`   // content type of the payload
	Flags     uint16              `order:"big"`   // processing flags
	HopCount  uint16              `order:"big"`   // number of hops so far
	ReplLevel uint16              `order:"big"`   // Replication level
	RfSize    uint16              `order:"big"`   // size of result filter
	PeerBF    *filter.BloomFilter ``              // bloomfilter to prevent loops
	Query     *crypto.HashCode    ``              // query hash
	ResFilter []byte              `size:"RfSize"` // result filter
	XQuery    []byte              `size:"*"`      // extended query
}

// NewDHTP2PGetMsg creates an empty DHT-P2P-Get message
func NewDHTP2PGetMsg() *DHTP2PGetMsg {
	return &DHTP2PGetMsg{
		MsgSize:   208,                        // message size without ResFiter and XQuery
		MsgType:   DHT_P2P_GET,                // DHT_P2P_GET (147)
		BType:     0,                          // no block type defined
		Flags:     0,                          // no flags defined
		HopCount:  0,                          // no hops
		ReplLevel: 0,                          // no replication level defined
		RfSize:    0,                          // no result filter
		PeerBF:    filter.NewBloomFilter(128), // allocate bloom filter
		Query:     crypto.NewHashCode(nil),    // empty Query hash
		ResFilter: nil,                        // empty result filter
		XQuery:    nil,                        // empty XQuery
	}
}

// String returns a human-readable representation of the message.
func (m *DHTP2PGetMsg) String() string {
	return fmt.Sprintf("DHTP2PGetMsg{btype=%s,hops=%d,flags=%d}",
		enums.BlockType(m.BType).String(), m.HopCount, m.Flags)
}

// Header returns the message header in a separate instance.
func (m *DHTP2PGetMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

//----------------------------------------------------------------------
// DHT-P2P-PUT messages are used by other peers in the DHT to
// request block storage.
//----------------------------------------------------------------------

// DHTP2PPutMsg wire layout
type DHTP2PPutMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // DHT_P2P_PUT (146)
}

// NewDHTP2PPutMsg creates an empty new DHTP2PPutMsg
func NewDHTP2PPutMsg() *DHTP2PPutMsg {
	return nil
}

// String returns a human-readable representation of the message.
func (m *DHTP2PPutMsg) String() string {
	return fmt.Sprintf("DHTP2PPutMsg{}")
}

// Header returns the message header in a separate instance.
func (m *DHTP2PPutMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

//----------------------------------------------------------------------
// DHT-P2P-RESULT messages are used to answer peer requests for
// bock retrieval.
//----------------------------------------------------------------------

// DHTP2PResultMsg wire layout
type DHTP2PResultMsg struct {
	MsgSize  uint16            `order:"big"`     // total size of message
	MsgType  uint16            `order:"big"`     // DHT_P2P_RESULT (148)
	BType    uint32            `order:"big"`     // Block type of result
	Reserved uint32            `order:"big"`     // Reserved for further use
	PutPathL uint16            `order:"big"`     // size of PUTPATH field
	GetPathL uint16            `order:"big"`     // size of GETPATH field
	Expires  util.AbsoluteTime ``                // expiration date
	Query    *crypto.HashCode  ``                // Query key for block
	PutPath  []byte            `size:"PutPathL"` // PUTPATH
	GetPath  []byte            `size:"GetPathL"` // GETPATH
	Block    []byte            `size:"*"`        // block data
}

// NewDHTP2PResultMsg creates a new empty DHTP2PResultMsg
func NewDHTP2PResultMsg() *DHTP2PResultMsg {
	return &DHTP2PResultMsg{
		MsgSize:  104,                          // size of empty message
		MsgType:  DHT_P2P_RESULT,               // DHT_P2P_RESULT (148)
		BType:    uint32(enums.BLOCK_TYPE_ANY), // type of returned block
		PutPathL: 0,                            // empty putpath
		PutPath:  nil,                          // -"-
		GetPathL: 0,                            // empty getpath
		GetPath:  nil,                          // -"-
		Block:    nil,                          // empty block
	}
}

// String returns a human-readable representation of the message.
func (m *DHTP2PResultMsg) String() string {
	return fmt.Sprintf("DHTP2ResultMsg{}")
}

// Header returns the message header in a separate instance.
func (m *DHTP2PResultMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

//----------------------------------------------------------------------
// DHT-P2P-HELLO
//
// A DHT-P2P-HELLO message is used to exchange information about transports
// with other DHT nodes. This struct is always followed by the actual
// network addresses of type "HelloAddress"
//----------------------------------------------------------------------

// DHTP2PHelloMsg is a message send by peers to announce their presence
type DHTP2PHelloMsg struct {
	MsgSize   uint16            `order:"big"` // total size of message
	MsgType   uint16            `order:"big"` // DHT_P2P_HELLO (157)
	Reserved  uint16            `order:"big"` // Reserved for further use
	NumAddr   uint16            `order:"big"` // Number of addresses in list
	Signature []byte            `size:"64"`   // Signature
	Expires   util.AbsoluteTime ``            // expiration time
	AddrList  []byte            `size:"*"`    // List of end-point addresses (HelloAddress)
}

// NewHelloMsgDHT creates an empty DHT_P2P_HELLO message.
func NewDHTP2PHelloMsg() *DHTP2PHelloMsg {
	// return empty HelloMessage
	exp := time.Now().Add(HelloAddressExpiration)
	return &DHTP2PHelloMsg{
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
func (m *DHTP2PHelloMsg) Addresses() (list []*util.Address, err error) {
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
		logger.Printf(logger.WARN, "[DHTP2PHelloMsg] Number of addresses does not match (got %d, expected %d)", num, m.NumAddr)
	}
	return
}

// SetAddresses adds addresses to the HELLO message.
func (m *DHTP2PHelloMsg) SetAddresses(list []*util.Address) {
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
func (m *DHTP2PHelloMsg) String() string {
	addrs, _ := m.Addresses()
	aList := ""
	for i, a := range addrs {
		if i > 0 {
			aList += ","
		}
		aList += a.URI()
	}
	return fmt.Sprintf("DHTP2PHelloMsg{expire:%s,addrs=%d:[%s]}", m.Expires, m.NumAddr, aList)
}

// Header returns the message header in a separate instance.
func (m *DHTP2PHelloMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

// Verify the message signature
func (m *DHTP2PHelloMsg) Verify(peer *util.PeerID) (bool, error) {
	// assemble signed data and public key
	sd := m.SignedData()
	pub := peer.PublicKey()
	sig, err := ed25519.NewEdSignatureFromBytes(m.Signature)
	if err != nil {
		return false, err
	}
	return pub.EdVerify(sd, sig)
}

// SetSignature stores a signature in the the HELLO block
func (m *DHTP2PHelloMsg) SetSignature(sig *ed25519.EdSignature) error {
	m.Signature = sig.Bytes()
	return nil
}

// SignedData assembles a data block for sign and verify operations.
func (m *DHTP2PHelloMsg) SignedData() []byte {
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
