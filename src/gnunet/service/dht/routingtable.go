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

package dht

import (
	"bytes"
	"context"
	"encoding/hex"
	"gnunet/config"
	"gnunet/crypto"
	"gnunet/service/dht/blocks"
	"gnunet/util"
	"sync"
	"time"

	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/math"
)

// Routing table constants
const (
	numK = 20 // number of entries per k-bucket
)

//======================================================================
// Peer address
//======================================================================

// PeerAddress is the identifier for a peer in the DHT network.
// It is the SHA-512 hash of the PeerID (public Ed25519 key).
type PeerAddress struct {
	Peer     *util.PeerID      // peer identifier
	Key      *crypto.HashCode  // address key is a sha512 hash
	lastSeen util.AbsoluteTime // time the peer was last seen
	lastUsed util.AbsoluteTime // time the peer was last used
}

// NewPeerAddress returns the DHT address of a peer.
func NewPeerAddress(peer *util.PeerID) *PeerAddress {
	return &PeerAddress{
		Peer:     peer,
		Key:      crypto.Hash(peer.Data),
		lastSeen: util.AbsoluteTimeNow(),
		lastUsed: util.AbsoluteTimeNow(),
	}
}

// NewQueryAddress returns a wrapped peer address for a query key
func NewQueryAddress(key *crypto.HashCode) *PeerAddress {
	return &PeerAddress{
		Peer:     nil,
		Key:      crypto.NewHashCode(key.Bits),
		lastSeen: util.AbsoluteTimeNow(),
		lastUsed: util.AbsoluteTimeNow(),
	}
}

// String returns a human-readble representation of an address.
func (addr *PeerAddress) String() string {
	return hex.EncodeToString(addr.Key.Bits)
}

// Equals returns true if two peer addresses are the same.
func (addr *PeerAddress) Equals(p *PeerAddress) bool {
	return bytes.Equal(addr.Key.Bits, p.Key.Bits)
}

// Distance between two addresses: returns a distance value and a
// bucket index (smaller index = less distant).
func (addr *PeerAddress) Distance(p *PeerAddress) (*math.Int, int) {
	d := make([]byte, 64)
	for i := range d {
		d[i] = addr.Key.Bits[i] ^ p.Key.Bits[i]
	}
	r := math.NewIntFromBytes(d)
	return r, 512 - r.BitLen()
}

//======================================================================
// Routing table implementation
//======================================================================

// RoutingTable holds the (local) routing table for a node.
// The index of of an address is the number of bits in the
// distance to the reference address, so smaller index means
// "nearer" to the reference address.
type RoutingTable struct {
	sync.RWMutex

	ref        *PeerAddress                          // reference address for distance
	buckets    []*Bucket                             // list of buckets
	list       *util.Map[string, *PeerAddress]       // keep list of peers
	l2nse      float64                               // log2 of estimated network size
	inProcess  bool                                  // flag if Process() is running
	cfg        *config.RoutingConfig                 // routing parameters
	helloCache *util.Map[string, *blocks.HelloBlock] // HELLO block cache
}

// NewRoutingTable creates a new routing table for the reference address.
func NewRoutingTable(ref *PeerAddress, cfg *config.RoutingConfig) *RoutingTable {
	// create routing table
	rt := &RoutingTable{
		ref:        ref,
		list:       util.NewMap[string, *PeerAddress](),
		buckets:    make([]*Bucket, 512),
		l2nse:      -1,
		inProcess:  false,
		cfg:        cfg,
		helloCache: util.NewMap[string, *blocks.HelloBlock](),
	}
	// fill buckets
	for i := range rt.buckets {
		rt.buckets[i] = NewBucket(numK)
	}
	return rt
}

//----------------------------------------------------------------------
// Peer management
//----------------------------------------------------------------------

// Add new peer address to routing table.
// Returns true if the entry was added, false otherwise.
func (rt *RoutingTable) Add(p *PeerAddress) bool {
	k := p.String()
	logger.Printf(logger.DBG, "[RT] Add(%s)", k)

	// check if peer is already known
	if px, ok := rt.list.Get(k); ok {
		logger.Println(logger.DBG, "[RT] --> already known")
		px.lastSeen = util.AbsoluteTimeNow()
		return false
	}

	// compute distance (bucket index) and insert address.
	_, idx := p.Distance(rt.ref)
	if rt.buckets[idx].Add(p) {
		logger.Println(logger.DBG, "[RT] --> entry added")
		p.lastUsed = util.AbsoluteTimeNow()
		rt.list.Put(k, p)
		return true
	}
	// Full bucket: we did not add the address to the routing table.
	logger.Println(logger.DBG, "[RT] --> bucket full -- discarded")
	return false
}

// Remove peer address from routing table.
// Returns true if the entry was removed, false otherwise.
func (rt *RoutingTable) Remove(p *PeerAddress) bool {
	k := p.String()
	logger.Printf(logger.DBG, "[RT] Remove(%s)", k)

	// compute distance (bucket index) and remove entry from bucket
	rc := false
	_, idx := p.Distance(rt.ref)
	if rt.buckets[idx].Remove(p) {
		logger.Println(logger.DBG, "[RT] --> entry removed from bucket and internal lists")
		rc = true
	} else {
		// remove from internal list
		logger.Println(logger.DBG, "[RT] --> entry removed from internal lists only")
	}
	rt.list.Delete(k)
	// delete from HELLO cache
	rt.helloCache.Delete(p.Peer.String())
	return rc
}

// Contains checks if a peer is available in the routing table
func (rt *RoutingTable) Contains(p *PeerAddress) bool {
	k := p.String()
	logger.Printf(logger.DBG, "[RT] Contains(%s)?", k)

	// check for peer in internal list
	px, ok := rt.list.Get(k)
	if !ok {
		logger.Println(logger.DBG, "[RT] --> NOT found in current list:")
		rt.list.ProcessRange(func(key string, val *PeerAddress) error {
			logger.Printf(logger.DBG, "[RT]    * %s", val)
			return nil
		}, true)
	} else {
		logger.Println(logger.DBG, "[RT] --> found in current list")
		px.lastSeen = util.AbsoluteTimeNow()
	}
	return ok
}

//----------------------------------------------------------------------

// Process a function f in the locked context of a routing table
func (rt *RoutingTable) Process(f func() error, readonly bool) error {
	// handle locking
	rt.lock(readonly)
	rt.inProcess = true
	defer func() {
		rt.inProcess = false
		rt.unlock(readonly)
	}()
	// call function in unlocked context
	return f()
}

//----------------------------------------------------------------------
// Routing functions
//----------------------------------------------------------------------

// SelectClosestPeer for a given peer address and peer filter.
func (rt *RoutingTable) SelectClosestPeer(p *PeerAddress, pf *blocks.PeerFilter) (n *PeerAddress) {
	// no writer allowed
	rt.RLock()
	defer rt.RUnlock()

	// find closest peer in routing table
	var dist *math.Int
	for _, b := range rt.buckets {
		if k, d := b.SelectClosestPeer(p, pf); n == nil || (d != nil && d.Cmp(dist) < 0) {
			dist = d
			n = k
		}
	}
	// mark peer as used
	if n != nil {
		n.lastUsed = util.AbsoluteTimeNow()
	}
	return
}

// SelectRandomPeer returns a random address from table (that is not
// included in the bloomfilter)
func (rt *RoutingTable) SelectRandomPeer(pf *blocks.PeerFilter) (p *PeerAddress) {
	// no writer allowed
	rt.RLock()
	defer rt.RUnlock()

	// select random entry from list
	var ok bool
	for {
		if _, p, ok = rt.list.GetRandom(); !ok {
			return nil
		}
		if !pf.Contains(p.Peer) {
			break
		}
	}
	// mark peer as used
	p.lastUsed = util.AbsoluteTimeNow()
	return
}

// SelectPeer selects a neighbor depending on the number of hops parameter.
// If hops < NSE this function MUST return SelectRandomPeer() and
// SelectClosestpeer() otherwise.
func (rt *RoutingTable) SelectPeer(p *PeerAddress, hops int, bf *blocks.PeerFilter) *PeerAddress {
	if float64(hops) < rt.l2nse {
		return rt.SelectRandomPeer(bf)
	}
	return rt.SelectClosestPeer(p, bf)
}

// IsClosestPeer returns true if p is the closest peer for k. Peers with a
// positive test in the Bloom filter are not considered. If p is nil, our
// reference address is used.
func (rt *RoutingTable) IsClosestPeer(p, k *PeerAddress, pf *blocks.PeerFilter) bool {
	// get closest peer in routing table
	n := rt.SelectClosestPeer(k, pf)
	// check SELF?
	if p == nil {
		// if no peer in routing table found
		if n == nil {
			// local peer is closest
			return true
		}
		// check if local distance is smaller than for best peer in routing table
		d0, _ := n.Distance(k)
		d1, _ := rt.ref.Distance(k)
		return d1.Cmp(d0) < 0
	}
	// check if p is closest peer
	return n.Equals(p)
}

// ComputeOutDegree computes the number of neighbors that a message should be forwarded to.
// The arguments are the desired replication level, the hop count of the message so far,
// and the base-2 logarithm of the current network size estimate (L2NSE) as provided by the
// underlay. The result is the non-negative number of next hops to select.
func (rt *RoutingTable) ComputeOutDegree(repl, hop uint16) int {
	hf := float64(hop)
	if hf > 4*rt.l2nse {
		return 0
	}
	if hf > 2*rt.l2nse {
		return 1
	}
	if repl == 0 {
		repl = 1
	} else if repl > 16 {
		repl = 16
	}
	rm1 := float64(repl - 1)
	return 1 + int(rm1/(rt.l2nse+rm1*hf))
}

//----------------------------------------------------------------------

// Heartbeat handler for periodic tasks
func (rt *RoutingTable) heartbeat(ctx context.Context) {

	// check for dead or expired peers
	logger.Println(logger.DBG, "[dht] RT heartbeat...")
	timeout := util.NewRelativeTime(time.Duration(rt.cfg.PeerTTL) * time.Second)
	if err := rt.Process(func() error {
		return rt.list.ProcessRange(func(k string, p *PeerAddress) error {
			// check if we can/need to drop a peer
			drop := timeout.Compare(p.lastSeen.Elapsed()) < 0
			if drop || timeout.Compare(p.lastUsed.Elapsed()) < 0 {
				logger.Printf(logger.DBG, "[RT] removing %v: %v, %v", p, p.lastSeen.Elapsed(), p.lastUsed.Elapsed())
				rt.Remove(p)
			}
			return nil
		}, false)
	}, false); err != nil {
		logger.Println(logger.ERROR, "[dht] RT heartbeat failed: "+err.Error())
	}

	// drop expired entries from the HELLO cache
	rt.helloCache.ProcessRange(func(key string, val *blocks.HelloBlock) error {
		if val.Expires.Expired() {
			rt.helloCache.Delete(key)
		}
		return nil
	}, false)

	// update the estimated network size
	// rt.l2nse = ...
}

//----------------------------------------------------------------------

func (rt *RoutingTable) BestHello(addr *PeerAddress, rf blocks.ResultFilter) (hb *blocks.HelloBlock, dist *math.Int) {
	// iterate over cached HELLOs to find (best) match first
	rt.helloCache.ProcessRange(func(key string, val *blocks.HelloBlock) error {
		// check if block is excluded by result filter
		if !rf.Contains(val) {
			// check for better match
			p := NewPeerAddress(val.PeerID)
			d, _ := addr.Distance(p)
			if hb == nil || d.Cmp(dist) < 0 {
				hb = val
				dist = d
			}
		}
		return nil
	}, true)
	return
}

// CacheHello adds a HELLO block to the list of cached entries.
func (rt *RoutingTable) CacheHello(hb *blocks.HelloBlock) {
	rt.helloCache.Put(hb.PeerID.String(), hb)
}

// GetHello returns a HELLO block for key k (if available)
func (rt *RoutingTable) GetHello(k string) (*blocks.HelloBlock, bool) {
	return rt.helloCache.Get(k)
}

//----------------------------------------------------------------------

// lock with given mode (if not in processing function)
func (rt *RoutingTable) lock(readonly bool) {
	if !rt.inProcess {
		if readonly {
			rt.RLock()
		} else {
			rt.Lock()
		}
	}
}

// lock with given mode (if not in processing function)
func (rt *RoutingTable) unlock(readonly bool) {
	if !rt.inProcess {
		if readonly {
			rt.RUnlock()
		} else {
			rt.Unlock()
		}
	}
}

//======================================================================
// Routing table buckets
//======================================================================

// Bucket holds peer entries with approx. same distance from node
type Bucket struct {
	sync.RWMutex

	list []*PeerAddress // list of peer addresses in bucket.
}

// NewBucket creates a new entry list of given size
func NewBucket(n int) *Bucket {
	return &Bucket{
		list: make([]*PeerAddress, 0, n),
	}
}

// Add peer address to the bucket if there is free space.
// Returns true if entry is added, false otherwise.
func (b *Bucket) Add(p *PeerAddress) bool {
	// only one writer and no readers
	b.Lock()
	defer b.Unlock()

	// check for free space in bucket
	if len(b.list) < numK {
		// append entry at the end
		b.list = append(b.list, p)
		return true
	}
	// full bucket: no further additions
	return false
}

// Remove peer address from the bucket.
// Returns true if entry is removed (found), false otherwise.
func (b *Bucket) Remove(p *PeerAddress) bool {
	// only one writer and no readers
	b.Lock()
	defer b.Unlock()

	for i, pe := range b.list {
		if pe.Equals(p) {
			// found entry: remove it
			b.list = append(b.list[:i], b.list[i+1:]...)
			return true
		}
	}
	return false
}

// SelectClosestPeer returns the entry with minimal distance to the given
// peer address; entries included in the bloom flter are ignored.
func (b *Bucket) SelectClosestPeer(p *PeerAddress, pf *blocks.PeerFilter) (n *PeerAddress, dist *math.Int) {
	// no writer allowed
	b.RLock()
	defer b.RUnlock()

	for _, addr := range b.list {
		// skip addresses in bloomfilter
		if pf.Contains(addr.Peer) {
			continue
		}
		// check for shorter distance
		if d, _ := p.Distance(addr); n == nil || d.Cmp(dist) < 0 {
			// remember best match
			dist = d
			n = addr
		}
	}
	return
}
