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

package blocks

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"
	"net/url"
	"strconv"
	"strings"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

// HELLO-related errors
var (
	ErrHelloExpired   = errors.New("expired HELLO")
	ErrHelloSignature = errors.New("failed HELLO signature")
)

//----------------------------------------------------------------------
// HELLO URLs are used for bootstrapping a node and for adding nodes
// outside of GNUnet message exchange (e.g. command-line tools)
//----------------------------------------------------------------------

const helloPrefix = "gnunet://hello/"

// HelloBlock is the DHT-managed block type for HELLO information.
// It is used to create and parse HELLO URLs.
// All addresses expire at the same time /this different from HELLO
// messages (see message.HelloMsg).
type HelloBlock struct {
	PeerID    *util.PeerID        ``         // peer identifier
	Signature *util.PeerSignature ``         // signature
	Expires   util.AbsoluteTime   ``         // Expiration date
	AddrBin   []byte              `size:"*"` // raw address data

	// transient attributes
	addrs []*util.Address // cooked address data
}

// SetAddresses adds a bulk of addresses for this HELLO block.
func (h *HelloBlock) SetAddresses(a []*util.Address) {
	h.addrs = util.Clone(a)
	if err := h.finalize(); err != nil {
		logger.Printf(logger.ERROR, "[HelloBlock.SetAddresses] failed: %s", err.Error())
	}
}

// Addresses returns the list of addresses
func (h *HelloBlock) Addresses() []*util.Address {
	return util.Clone(h.addrs)
}

// ParseHelloURL parses a HELLO URL of the following form:
//     gnunet://hello/<PeerID>/<signature>/<expire>?<addrs>
// The addresses are encoded.
func ParseHelloURL(u string, checkExpiry bool) (h *HelloBlock, err error) {
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
	h = new(HelloBlock)

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
	h.Signature = util.NewPeerSignature(buf)

	// (3) split last element into parts
	q := strings.SplitN(p[2], "?", 2)

	// (4) parse expiration date
	var exp uint64
	if exp, err = strconv.ParseUint(q[0], 10, 64); err != nil {
		return
	}
	h.Expires = util.NewAbsoluteTimeEpoch(exp)
	if checkExpiry && h.Expires.Expired() {
		err = ErrHelloExpired
		return
	}

	// (5) process addresses.
	h.addrs = make([]*util.Address, 0)
	for _, a := range strings.Split(q[1], "&") {
		// reformat to standard address format
		ap := strings.SplitN(a, "=", 2)
		var q string
		if q, err = url.QueryUnescape(ap[1]); err != nil {
			return
		}
		as := ap[0] + "://" + q
		// parse address and append it to list
		var addr *util.Address
		if addr, err = util.ParseAddress(as); err != nil {
			return
		}
		h.addrs = append(h.addrs, addr)
	}

	// (6) generate raw address data so block is complete
	if err = h.finalize(); err != nil {
		return
	}

	// check signature
	var ok bool
	if ok, err = h.Verify(); err != nil {
		return
	}
	if !ok {
		err = ErrHelloSignature
	}
	return
}

// ParseHelloFromBytes converts a byte array into a HelloBlock instance.
func ParseHelloFromBytes(buf []byte) (h *HelloBlock, err error) {
	h = new(HelloBlock)
	if err = data.Unmarshal(h, buf); err == nil {
		err = h.finalize()
	}
	return
}

// finalize block data (generate dependent fields)
func (h *HelloBlock) finalize() (err error) {
	if h.addrs == nil {
		// read addresses from the binary representation
		pos := 0
		h.addrs = make([]*util.Address, 0)
		for {
			var as string
			as, pos = util.ReadCString(h.AddrBin, pos)
			if pos == -1 {
				break
			}
			var addr *util.Address
			if addr, err = util.ParseAddress(as); err != nil {
				return
			}
			h.addrs = append(h.addrs, addr)
		}
	} else if h.AddrBin == nil {
		// generate binary representation of addresses
		wrt := new(bytes.Buffer)
		for _, a := range h.addrs {
			wrt.WriteString(a.URI())
			wrt.WriteByte(0)
		}
		h.AddrBin = wrt.Bytes()
	}
	return
}

// Return the block type
func (h *HelloBlock) Type() enums.BlockType {
	return enums.BLOCK_TYPE_DHT_URL_HELLO
}

// Bytes returns the raw block data
func (h *HelloBlock) Bytes() []byte {
	buf, err := data.Marshal(h)
	if err != nil {
		logger.Println(logger.ERROR, "[hello] Failed to serialize HELLO block: "+err.Error())
		buf = nil
	}
	return buf
}

// Expire returns the block expiration
func (h *HelloBlock) Expire() util.AbsoluteTime {
	return h.Expires
}

// String returns the human-readable representation of a block
func (h *HelloBlock) String() string {
	return fmt.Sprintf("HelloBlock{peer=%s,expires=%s,addrs=[%d]}",
		h.PeerID, h.Expires, len(h.Addresses()))
}

// URL returns the HELLO URL for the data.
func (h *HelloBlock) URL() string {
	u := fmt.Sprintf("%s%s/%s/%d?",
		helloPrefix,
		h.PeerID.String(),
		util.EncodeBinaryToString(h.Signature.Data),
		h.Expires.Epoch(),
	)
	for i, a := range h.addrs {
		if i > 0 {
			u += "&"
		}
		au := a.URI()
		p := strings.SplitN(au, "://", 2)
		u += p[0] + "=" + url.QueryEscape(p[1])
	}
	return u
}

// Equals returns true if two HELLOs are the same. The expiration
// timestamp is ignored in the comparison.
func (h *HelloBlock) Equals(g *HelloBlock) bool {
	if !h.PeerID.Equals(g.PeerID) ||
		!util.Equals(h.Signature.Data, g.Signature.Data) ||
		len(h.addrs) != len(g.addrs) {
		return false
	}
	for i, a := range h.addrs {
		if !a.Equals(g.addrs[i]) {
			return false
		}
	}
	return true
}

// Verify the integrity of the HELLO data
func (h *HelloBlock) Verify() (bool, error) {
	// assemble signed data and public key
	sd := h.SignedData()
	pub := ed25519.NewPublicKeyFromBytes(h.PeerID.Data)
	sig, err := ed25519.NewEdSignatureFromBytes(h.Signature.Data)
	if err != nil {
		return false, err
	}
	return pub.EdVerify(sd, sig)
}

// SetSignature stores a signature in the the HELLO block
func (h *HelloBlock) SetSignature(sig *util.PeerSignature) error {
	h.Signature = sig
	return nil
}

// SignedData assembles a data block for sign and verify operations.
func (h *HelloBlock) SignedData() []byte {
	// hash address block
	hAddr := sha512.Sum512(h.AddrBin)
	var size uint32 = 80
	purpose := uint32(enums.SIG_HELLO)

	// assemble signed data
	buf := new(bytes.Buffer)
	var n int
	err := binary.Write(buf, binary.BigEndian, size)
	if err == nil {
		if err = binary.Write(buf, binary.BigEndian, purpose); err == nil {
			if err = binary.Write(buf, binary.BigEndian, h.Expires.Epoch()*1000000); err == nil {
				if n, err = buf.Write(hAddr[:]); err == nil {
					if n != len(hAddr[:]) {
						err = errors.New("signed data size mismatch")
					}
				}
			}
		}
	}
	if err != nil {
		logger.Printf(logger.ERROR, "[HelloBlock.SignedData] failed: %s", err.Error())
	}
	return buf.Bytes()
}

//----------------------------------------------------------------------
// HELLO block handler
//----------------------------------------------------------------------

// HelloBlockHandler methods related to HELLO blocks
type HelloBlockHandler struct{}

// Parse a block instance from binary data
func (bh *HelloBlockHandler) ParseBlock(buf []byte) (Block, error) {
	return ParseHelloFromBytes(buf)
}

// ValidateHelloBlockQuery validates query parameters for a
// DHT-GET request for HELLO blocks.
func (bh *HelloBlockHandler) ValidateBlockQuery(key *crypto.HashCode, xquery []byte) bool {
	// no xquery parameters allowed.
	return len(xquery) == 0
}

// ValidateBlockKey returns true if the block key is the same as the
// query key used to access the block.
func (bh *HelloBlockHandler) ValidateBlockKey(b Block, key *crypto.HashCode) bool {
	// check for matching keys
	bkey := bh.DeriveBlockKey(b)
	if bkey == nil {
		return false
	}
	return key.Equals(bkey)
}

// DeriveBlockKey is used to synthesize the block key from the block
// payload as part of PutMessage and ResultMessage processing. The special
// return value of 'nil' implies that this block type does not permit
// deriving the key from the block. A Key may be returned for a block that
// is ill-formed.
func (bh *HelloBlockHandler) DeriveBlockKey(b Block) *crypto.HashCode {
	hb, ok := b.(*HelloBlock)
	if !ok {
		return nil
	}
	// key must be the hash of the peer id
	return crypto.Hash(hb.PeerID.Bytes())
}

// ValidateBlockStoreRequest is used to evaluate a block payload as part of
// PutMessage and ResultMessage processing.
func (bh *HelloBlockHandler) ValidateBlockStoreRequest(b Block) bool {
	// TODO: verify block payload
	return true
}

// SetupResultFilter is used to setup an empty result filter. The arguments
// are the set of results that must be filtered at the initiator, and a
// MUTATOR value which MAY be used to deterministically re-randomize
// probabilistic data structures.
func (bh *HelloBlockHandler) SetupResultFilter(filterSize int, mutator uint32) ResultFilter {
	return NewHelloResultFilter(filterSize, mutator)
}

// ParseResultFilter from binary data
func (bh *HelloBlockHandler) ParseResultFilter(data []byte) ResultFilter {
	return NewHelloResultFilterFromBytes(data)
}

// FilterResult is used to filter results against specific queries. This
// function does not check the validity of the block itself or that it
// matches the given key, as this must have been checked earlier. Thus,
// locally stored blocks from previously observed ResultMessages and
// PutMessages use this function to perform filtering based on the request
// parameters of a particular GET operation. Possible values for the
// FilterEvaluationResult are defined above. If the main evaluation result
// is RF_MORE, the function also returns and updated result filter where
// the block is added to the set of filtered replies. An implementation is
// not expected to actually differentiate between the RF_DUPLICATE and
// RF_IRRELEVANT return values: in both cases the block is ignored for
// this query.
func (bh *HelloBlockHandler) FilterResult(b Block, key *crypto.HashCode, rf ResultFilter, xQuery []byte) int {
	if rf.Contains(b) {
		return RF_DUPLICATE
	}
	rf.Add(b)
	return RF_LAST
}

//----------------------------------------------------------------------
// HELLO result filter
//----------------------------------------------------------------------

// HelloResultFilter is a result  filter implementation for HELLO blocks
type HelloResultFilter struct {
	bf *BloomFilter
}

// NewHelloResultFilter initializes an empty resut filter
func NewHelloResultFilter(filterSize int, mutator uint32) *HelloResultFilter {
	// HELLO result filters are BloomFilters with a mutator
	rf := new(HelloResultFilter)
	rf.bf = NewBloomFilter(filterSize)
	rf.bf.SetMutator(mutator)
	return rf
}

// NewHelloResultFilterFromBytes creates a new result filter from a binary
// representation: 'data' is the concatenaion 'mutator|bloomfilter'.
// If 'withMutator' is false, no mutator is used.
func NewHelloResultFilterFromBytes(data []byte) *HelloResultFilter {
	//logger.Printf(logger.DBG, "[filter] FromBytes = %d:%s (mutator: %v)",len(data), hex.EncodeToString(data), withMutator)

	// handle mutator input
	mSize := 4
	rf := new(HelloResultFilter)
	rf.bf = &BloomFilter{
		Bits: util.Clone(data[mSize:]),
	}
	if mSize > 0 {
		rf.bf.SetMutator(data[:mSize])
	}
	return rf
}

// Add a HELLO block to th result filter
func (rf *HelloResultFilter) Add(b Block) {
	if hb, ok := b.(*HelloBlock); ok {
		hAddr := sha512.Sum512(hb.AddrBin)
		rf.bf.Add(hAddr[:])
	}
}

// Contains checks if a block is contained in the result filter
func (rf *HelloResultFilter) Contains(b Block) bool {
	if hb, ok := b.(*HelloBlock); ok {
		hAddr := sha512.Sum512(hb.AddrBin)
		return rf.bf.Contains(hAddr[:])
	}
	return false
}

// ContainsHash checks if a block hash is contained in the result filter
func (rf *HelloResultFilter) ContainsHash(bh *crypto.HashCode) bool {
	return rf.bf.Contains(bh.Bits)
}

// Bytes returns a binary representation of a HELLO result filter
func (rf *HelloResultFilter) Bytes() []byte {
	return rf.bf.Bytes()
}

// Compare two HELLO result filters
func (rf *HelloResultFilter) Compare(t ResultFilter) int {
	trf, ok := t.(*HelloResultFilter)
	if !ok {
		return CMP_DIFFER
	}
	return rf.bf.Compare(trf.bf)
}

// Merge two HELLO result filters
func (rf *HelloResultFilter) Merge(t ResultFilter) bool {
	trf, ok := t.(*HelloResultFilter)
	if !ok {
		return false
	}
	return rf.bf.Merge(trf.bf)
}
