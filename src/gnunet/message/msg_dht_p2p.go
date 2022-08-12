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
	"errors"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/service/dht/blocks"
	"gnunet/service/dht/path"
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
	MsgSize    uint16             `order:"big"`   // total size of message
	MsgType    uint16             `order:"big"`   // DHT_P2P_GET (147)
	BType      uint32             `order:"big"`   // content type of the payload
	Flags      uint16             `order:"big"`   // processing flags
	HopCount   uint16             `order:"big"`   // number of hops so far
	ReplLevel  uint16             `order:"big"`   // Replication level
	RfSize     uint16             `order:"big"`   // size of result filter
	PeerFilter *blocks.PeerFilter ``              // peer filter to prevent loops
	Query      *crypto.HashCode   ``              // query hash
	ResFilter  []byte             `size:"RfSize"` // result filter
	XQuery     []byte             `size:"*"`      // extended query
}

// NewDHTP2PGetMsg creates an empty DHT-P2P-Get message
func NewDHTP2PGetMsg() *DHTP2PGetMsg {
	return &DHTP2PGetMsg{
		MsgSize:    208,                     // message size without ResFiter and XQuery
		MsgType:    DHT_P2P_GET,             // DHT_P2P_GET (147)
		BType:      0,                       // no block type defined
		Flags:      0,                       // no flags defined
		HopCount:   0,                       // no hops
		ReplLevel:  0,                       // no replication level defined
		RfSize:     0,                       // no result filter
		PeerFilter: blocks.NewPeerFilter(),  // allocate bloom filter
		Query:      crypto.NewHashCode(nil), // empty Query hash
		ResFilter:  nil,                     // empty result filter
		XQuery:     nil,                     // empty XQuery
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

// Update message (forwarding)
func (m *DHTP2PGetMsg) Update(pf *blocks.PeerFilter, rf blocks.ResultFilter, hop uint16) *DHTP2PGetMsg {
	buf := rf.Bytes()
	ns := uint16(len(buf))
	return &DHTP2PGetMsg{
		MsgSize:    m.MsgSize - m.RfSize + ns,
		MsgType:    DHT_P2P_GET,
		BType:      m.BType,
		Flags:      m.Flags,
		HopCount:   hop,
		ReplLevel:  m.ReplLevel,
		RfSize:     ns,
		PeerFilter: pf.Clone(),
		Query:      m.Query,
		ResFilter:  buf,
		XQuery:     util.Clone(m.XQuery),
	}
}

//----------------------------------------------------------------------
// DHT-P2P-PUT messages are used by other peers in the DHT to
// request block storage.
//----------------------------------------------------------------------

// DHTP2PPutMsg wire layout
type DHTP2PPutMsg struct {
	MsgSize     uint16              `order:"big"`    // total size of message
	MsgType     uint16              `order:"big"`    // DHT_P2P_PUT (146)
	BType       uint32              `order:"big"`    // block type
	Flags       uint16              `order:"big"`    // processing flags
	HopCount    uint16              `order:"big"`    // message hops
	ReplLvl     uint16              `order:"big"`    // replication level
	PathL       uint16              `order:"big"`    // path length
	Expiration  util.AbsoluteTime   ``               // expiration date
	PeerFilter  *blocks.PeerFilter  ``               // peer bloomfilter
	Key         *crypto.HashCode    ``               // query key to block
	TruncOrigin *util.PeerID        `opt:"(IsUsed)"` // truncated origin (if TRUNCATED flag set)
	PutPath     []*path.Entry       `size:"PathL"`   // PUT path
	LastSig     *util.PeerSignature `opt:"(IsUsed)"` // signature of last hop (if RECORD_ROUTE flag is set)
	Block       []byte              `size:"*"`       // block data
}

// NewDHTP2PPutMsg creates an empty new DHTP2PPutMsg
func NewDHTP2PPutMsg() *DHTP2PPutMsg {
	return &DHTP2PPutMsg{
		MsgSize:     218,                      // total size without path and block data
		MsgType:     DHT_P2P_PUT,              // DHT_P2P_PUT (146)
		BType:       0,                        // block type
		Flags:       0,                        // processing flags
		HopCount:    0,                        // message hops
		ReplLvl:     0,                        // replication level
		PathL:       0,                        // no PUT path
		Expiration:  util.AbsoluteTimeNever(), // expiration date
		PeerFilter:  blocks.NewPeerFilter(),   // peer bloom filter
		Key:         crypto.NewHashCode(nil),  // query key
		TruncOrigin: nil,                      // no truncated path
		PutPath:     make([]*path.Entry, 0),   // empty PUT path
		LastSig:     nil,                      // no signature from last hop
		Block:       nil,                      // no block data
	}
}

// IsUsed returns true if an optional field is used
func (m *DHTP2PPutMsg) IsUsed(field string) bool {
	switch field {
	case "Origin":
		return m.Flags&enums.DHT_RO_TRUNCATED != 0
	case "LastSig":
		return m.Flags&enums.DHT_RO_RECORD_ROUTE != 0
	}
	return false
}

//----------------------------------------------------------------------

// Update message (forwarding)
func (m *DHTP2PPutMsg) Update(p *path.Path, pf *blocks.PeerFilter, hop uint16) *DHTP2PPutMsg {
	msg := NewDHTP2PPutMsg()
	msg.Flags = m.Flags
	msg.HopCount = hop
	msg.PathL = p.NumList
	msg.Expiration = m.Expiration
	msg.PeerFilter = pf
	msg.Key = m.Key.Clone()
	msg.TruncOrigin = p.TruncOrigin
	msg.PutPath = util.Clone(p.List)
	msg.LastSig = p.LastSig
	msg.Block = util.Clone(m.Block)
	msg.SetPath(p)
	return msg
}

//----------------------------------------------------------------------
// Path handling (get/set path in message)
//----------------------------------------------------------------------

// Path returns the current path from message
func (m *DHTP2PPutMsg) Path(sender *util.PeerID) *path.Path {
	// create a "real" path list from message data
	pth := path.NewPath(crypto.Hash(m.Block), m.Expiration)

	// return empty path if recording is switched off
	if m.Flags&enums.DHT_RO_RECORD_ROUTE == 0 {
		return pth
	}

	// handle truncate origin
	if m.Flags&enums.DHT_RO_TRUNCATED == 1 {
		if m.TruncOrigin == nil {
			logger.Printf(logger.WARN, "[path] truncated but no origin - flag reset")
			m.Flags &^= enums.DHT_RO_TRUNCATED
		} else {
			pth.TruncOrigin = m.TruncOrigin
			pth.Flags |= path.PathTruncated
		}
	}

	// copy path elements
	pth.List = util.Clone(m.PutPath)
	pth.NumList = uint16(len(pth.List))

	// handle last hop signature
	if m.LastSig == nil {
		logger.Printf(logger.WARN, "[path]  - last hop signature missing - path reset")
		return path.NewPath(crypto.Hash(m.Block), m.Expiration)
	}
	pth.Flags |= path.PathLastHop
	pth.LastSig = m.LastSig
	pth.LastHop = sender
	return pth
}

// Set path in message; corrects the message size accordingly
func (m *DHTP2PPutMsg) SetPath(p *path.Path) {

	// return if recording is switched off (don't touch path)
	if m.Flags&enums.DHT_RO_RECORD_ROUTE == 0 {
		return
	}
	// compute old path size
	var pes uint
	if len(m.PutPath) > 0 {
		pes = m.PutPath[0].Size()
	}
	oldSize := uint(len(m.PutPath)) * pes
	if m.TruncOrigin != nil {
		oldSize += m.TruncOrigin.Size()
	}
	if m.LastSig != nil {
		oldSize += m.LastSig.Size()
	}
	// if no new path is defined,...
	if p == nil {
		// ... remove existing path
		m.TruncOrigin = nil
		m.PutPath = nil
		m.LastSig = nil
		m.PathL = 0
		m.Flags &^= enums.DHT_RO_TRUNCATED
		m.MsgSize -= uint16(oldSize)
		return
	}
	// adjust message size
	m.MsgSize += uint16(p.Size() - oldSize)

	// transfer path data
	if p.TruncOrigin != nil {
		// truncated path
		m.Flags |= enums.DHT_RO_TRUNCATED
		m.TruncOrigin = p.TruncOrigin
	}
	m.PutPath = util.Clone(p.List)
	m.PathL = uint16(len(m.PutPath))
	if p.LastSig != nil {
		m.LastSig = p.LastSig
	}
}

//----------------------------------------------------------------------

// String returns a human-readable representation of the message.
func (m *DHTP2PPutMsg) String() string {
	return fmt.Sprintf("DHTP2PPutMsg{btype=%s,hops=%d,flags=%d}",
		enums.BlockType(m.BType).String(), m.HopCount, m.Flags)
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
	MsgSize     uint16              `order:"big"`      // total size of message
	MsgType     uint16              `order:"big"`      // DHT_P2P_RESULT (148)
	BType       uint32              `order:"big"`      // Block type of result
	Flags       uint32              `order:"big"`      // Message flags
	PutPathL    uint16              `order:"big"`      // size of PUTPATH field
	GetPathL    uint16              `order:"big"`      // size of GETPATH field
	Expires     util.AbsoluteTime   ``                 // expiration date
	Query       *crypto.HashCode    ``                 // Query key for block
	TruncOrigin *util.PeerID        `opt:"(IsUsed)"`   // truncated origin (if TRUNCATED flag set)
	PathList    []*path.Entry       `size:"(NumPath)"` // PATH
	LastSig     *util.PeerSignature `size:"(IsUsed)"`  // signature of last hop (if RECORD_ROUTE flag is set)
	Block       []byte              `size:"*"`         // block data
}

// NewDHTP2PResultMsg creates a new empty DHTP2PResultMsg
func NewDHTP2PResultMsg() *DHTP2PResultMsg {
	return &DHTP2PResultMsg{
		MsgSize:     88,                           // size of empty message
		MsgType:     DHT_P2P_RESULT,               // DHT_P2P_RESULT (148)
		BType:       uint32(enums.BLOCK_TYPE_ANY), // type of returned block
		TruncOrigin: nil,                          // no truncated origin
		PutPathL:    0,                            // empty putpath
		GetPathL:    0,                            // empty getpath
		PathList:    nil,                          // empty path list (put+get)
		LastSig:     nil,                          // no recorded route
		Block:       nil,                          // empty block
	}
}

// IsUsed returns if an optional field is present
func (m *DHTP2PResultMsg) IsUsed(field string) bool {
	switch field {
	case "Origin":
		return m.Flags&enums.DHT_RO_TRUNCATED != 0
	case "LastSig":
		return m.Flags&enums.DHT_RO_RECORD_ROUTE != 0
	}
	return false
}

// NumPath returns the total number of entries in path
func (m *DHTP2PResultMsg) NumPath(field string) uint {
	return uint(m.GetPathL + m.PutPathL)
}

//----------------------------------------------------------------------
// Path handling (get/set path in message)
//----------------------------------------------------------------------

// Path returns the current path from message
func (m *DHTP2PResultMsg) Path(sender *util.PeerID) *path.Path {
	// create a "real" path list from message data
	pth := path.NewPath(crypto.Hash(m.Block), m.Expires)

	// return empty path if recording is switched off
	if m.Flags&enums.DHT_RO_RECORD_ROUTE == 0 {
		return pth
	}
	// handle truncate origin
	if m.Flags&enums.DHT_RO_TRUNCATED == 1 {
		if m.TruncOrigin == nil {
			logger.Printf(logger.WARN, "[path] truncated but no origin - flag reset")
			m.Flags &^= enums.DHT_RO_TRUNCATED
		} else {
			pth.TruncOrigin = m.TruncOrigin
			pth.Flags |= path.PathTruncated
		}
	}
	// copy path elements
	pth.List = util.Clone(m.PathList)
	pth.NumList = uint16(len(pth.List))

	// check consistent length values; adjust if mismatched
	if m.GetPathL+m.PutPathL != pth.NumList {
		logger.Printf(logger.WARN, "[path] Inconsistent PATH length -- adjusting...")
		if sp := pth.NumList - m.PutPathL; sp > 0 {
			pth.SplitPos = sp
		} else {
			pth.SplitPos = 0
		}
	} else {
		pth.SplitPos = pth.NumList - m.PutPathL
	}
	// handle last hop signature
	if m.LastSig == nil {
		logger.Printf(logger.WARN, "[path]  - last hop signature missing - path reset")
		return path.NewPath(crypto.Hash(m.Block), m.Expires)
	}
	pth.Flags |= path.PathLastHop
	pth.LastSig = m.LastSig
	pth.LastHop = sender
	return pth
}

// Set path in message; corrects the message size accordingly
func (m *DHTP2PResultMsg) SetPath(p *path.Path) {

	// return if recording is switched off (don't touch path)
	if m.Flags&enums.DHT_RO_RECORD_ROUTE == 0 {
		return
	}
	// compute old path size
	var pes uint
	if len(m.PathList) > 0 {
		pes = m.PathList[0].Size()
	}
	oldSize := uint(len(m.PathList)) * pes
	if m.TruncOrigin != nil {
		oldSize += m.TruncOrigin.Size()
	}
	if m.LastSig != nil {
		oldSize += m.LastSig.Size()
	}
	// if no new path is defined,...
	if p == nil {
		// ... remove existing path
		m.TruncOrigin = nil
		m.PathList = make([]*path.Entry, 0)
		m.LastSig = nil
		m.GetPathL = 0
		m.PutPathL = 0
		m.Flags &^= enums.DHT_RO_TRUNCATED
		m.MsgSize -= uint16(oldSize)
		return
	}
	// adjust message size
	m.MsgSize += uint16(p.Size() - oldSize)

	// transfer path data
	if p.TruncOrigin != nil {
		// truncated path
		m.Flags |= enums.DHT_RO_TRUNCATED
		m.TruncOrigin = p.TruncOrigin
	}
	m.PathList = util.Clone(p.List)
	m.PutPathL = p.SplitPos
	m.GetPathL = p.NumList - p.SplitPos
	if p.LastSig != nil {
		m.LastSig = p.LastSig
	}
}

//----------------------------------------------------------------------

// Update message (forwarding)
func (m *DHTP2PResultMsg) Update(pth *path.Path) *DHTP2PResultMsg {
	// clone old message
	msg := &DHTP2PResultMsg{
		MsgSize:     m.MsgSize,
		MsgType:     m.MsgType,
		BType:       m.BType,
		Flags:       m.Flags,
		PutPathL:    m.PutPathL,
		GetPathL:    m.GetPathL,
		Expires:     m.Expires,
		Query:       m.Query.Clone(),
		TruncOrigin: m.TruncOrigin,
		PathList:    util.Clone(m.PathList),
		LastSig:     m.LastSig,
		Block:       util.Clone(m.Block),
	}
	// set new path
	msg.SetPath(pth)
	return msg
}

//----------------------------------------------------------------------

// String returns a human-readable representation of the message.
func (m *DHTP2PResultMsg) String() string {
	return fmt.Sprintf("DHTP2PResultMsg{btype=%s,putl=%d,getl=%d}",
		enums.BlockType(m.BType).String(), m.PutPathL, m.GetPathL)
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
	MsgSize   uint16              `order:"big"` // total size of message
	MsgType   uint16              `order:"big"` // DHT_P2P_HELLO (157)
	Reserved  uint16              `order:"big"` // Reserved for further use
	NumAddr   uint16              `order:"big"` // Number of addresses in list
	Signature *util.PeerSignature ``            // Signature
	Expires   util.AbsoluteTime   ``            // expiration time
	AddrList  []byte              `size:"*"`    // List of end-point addresses (HelloAddress)
}

// NewHelloMsgDHT creates an empty DHT_P2P_HELLO message.
func NewDHTP2PHelloMsg() *DHTP2PHelloMsg {
	// return empty HelloMessage
	exp := time.Now().Add(HelloAddressExpiration)
	return &DHTP2PHelloMsg{
		MsgSize:   80,                         // size without 'AddrList'
		MsgType:   DHT_P2P_HELLO,              // DHT_P2P_HELLO (157)
		Reserved:  0,                          // not used here
		NumAddr:   0,                          // start with empty address list
		Signature: util.NewPeerSignature(nil), // signature
		Expires:   util.NewAbsoluteTime(exp),  // default expiration
		AddrList:  make([]byte, 0),            // list of addresses
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
	pub := ed25519.NewPublicKeyFromBytes(peer.Data)
	sig, err := ed25519.NewEdSignatureFromBytes(m.Signature.Data)
	if err != nil {
		return false, err
	}
	return pub.EdVerify(sd, sig)
}

// SetSignature stores a signature in the the HELLO block
func (m *DHTP2PHelloMsg) SetSignature(sig *util.PeerSignature) error {
	m.Signature = sig
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
	var n int
	err := binary.Write(buf, binary.BigEndian, size)
	if err == nil {
		if err = binary.Write(buf, binary.BigEndian, purpose); err == nil {
			if err = binary.Write(buf, binary.BigEndian, m.Expires.Epoch()*1000000); err == nil {
				if n, err = buf.Write(hAddr[:]); err == nil {
					if n != len(hAddr[:]) {
						err = errors.New("write failed")
					}
				}
			}
		}
	}
	if err != nil {
		logger.Printf(logger.ERROR, "[DHTP2PHelloMsg.SignedData] failed: %s", err.Error())
	}
	return buf.Bytes()
}
