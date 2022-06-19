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
// messages (see message.HeeloMsg).
type HelloBlock struct {
	PeerID    *util.PeerID      ``          // peer identifier
	Signature []byte            `size:"64"` // signature
	Expire    util.AbsoluteTime ``          // Expiration date
	AddrBin   []byte            `size:"*"`  // raw address data

	// transient attributes
	addrs []*util.Address // cooked address data
}

// SetAddresses adds a bulk of addresses for this HELLO block.
func (h *HelloBlock) SetAddresses(a []*util.Address) {
	h.addrs = util.Clone(a)
	h.finalize()
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
	if h.Signature, err = util.DecodeStringToBinary(p[1], 64); err != nil {
		return
	}

	// (3) split last element into parts
	q := strings.SplitN(p[2], "?", 2)

	// (4) parse expiration date
	var exp uint64
	if exp, err = strconv.ParseUint(q[0], 10, 64); err != nil {
		return
	}
	h.Expire = util.NewAbsoluteTimeEpoch(exp)
	if checkExpiry && h.Expire.Expired() {
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
	h.finalize()

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

// URL returns the HELLO URL for the data.
func (h *HelloBlock) URL() string {
	u := fmt.Sprintf("%s%s/%s/%d?",
		helloPrefix,
		h.PeerID.String(),
		util.EncodeBinaryToString(h.Signature),
		h.Expire.Epoch(),
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
// timestamp is ignored in the comparision.
func (h *HelloBlock) Equals(g *HelloBlock) bool {
	if !h.PeerID.Equals(g.PeerID) ||
		!util.Equals(h.Signature, g.Signature) ||
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
	pub := h.PeerID.PublicKey()
	sig, err := ed25519.NewEdSignatureFromBytes(h.Signature)
	if err != nil {
		return false, err
	}
	return pub.EdVerify(sd, sig)
}

// SetSignature stores a signature in the the HELLO block
func (h *HelloBlock) SetSignature(sig *ed25519.EdSignature) error {
	h.Signature = sig.Bytes()
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
	binary.Write(buf, binary.BigEndian, size)
	binary.Write(buf, binary.BigEndian, purpose)
	binary.Write(buf, binary.BigEndian, h.Expire.Epoch()*1000000)
	buf.Write(hAddr[:])
	return buf.Bytes()
}

//----------------------------------------------------------------------

type HelloBlockHandler struct{}

// ValidateHelloBlockQuery validates query parameters for a
// DHT-GET request for HELLO blocks.
func (bh *HelloBlockHandler) ValidateBlockQuery(key *crypto.HashCode, xquery []byte) bool {
	// no xquery parameters allowed.
	return len(xquery) == 0
}

// SetupResultFilter is used to setup an empty result filter. The arguments
// are the set of results that must be filtered at the initiator, and a
// MUTATOR value which MAY be used to deterministically re-randomize
// probabilistic data structures.
func (bh *HelloBlockHandler) SetupResultFilter(filterSize int, mutator uint32) []byte {
	return nil
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
// not expected to actually differenciate between the RF_DUPLICATE and
// RF_IRRELEVANT return values: in both cases the block is ignored for
// this query.
func (bh *HelloBlockHandler) FilterResult(b Block, key *crypto.HashCode, rf []byte, xQuery []byte) ([]byte, []byte) {
	return nil, nil
}

// ValidateBlockStoreRequest is used to evaluate a block payload as part of
// PutMessage and ResultMessage processing.
func (bh *HelloBlockHandler) ValidateBlockStoreRequest(b Block) bool {
	return false
}
