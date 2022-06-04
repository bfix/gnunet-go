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
	"crypto/sha512"
	"encoding/hex"
	"gnunet/util"
	"math/rand"
	"sync"
	"time"

	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/math"
)

var (
	// routing table hash function: defines number of
	// buckets and size of peer addresses
	rtHash = sha512.New
)

// Routing table contants (adjust with changing hash function)
const (
	numBuckets = 512 // number of bits of hash function result
	numK       = 20  // number of entries per k-bucket
	sizeAddr   = 64  // size of peer address in bytes
)

//======================================================================
//======================================================================

// PeerAddress is the identifier for a peer in the DHT network.
// It is the SHA-512 hash of the PeerID (public Ed25519 key).
type PeerAddress struct {
	addr      [sizeAddr]byte    // hash value as bytes
	connected bool              // is peer connected?
	lastSeen  util.AbsoluteTime // time the peer was last seen
	lastUsed  util.AbsoluteTime // time the peer was last used
}

// NewPeerAddress returns the DHT address of a peer.
func NewPeerAddress(peer *util.PeerID) *PeerAddress {
	r := new(PeerAddress)
	h := rtHash()
	h.Write(peer.Key)
	copy(r.addr[:], h.Sum(nil))
	r.lastSeen = util.AbsoluteTimeNow()
	r.lastUsed = util.AbsoluteTimeNow()
	return r
}

// String returns a human-readble representation of an address.
func (addr *PeerAddress) String() string {
	return hex.EncodeToString(addr.addr[:])
}

// Equals returns true if two peer addresses are the same.
func (addr *PeerAddress) Equals(p *PeerAddress) bool {
	return bytes.Equal(addr.addr[:], p.addr[:])
}

// Distance between two addresses: returns a distance value and a
// bucket index (smaller index = less distant).
func (addr *PeerAddress) Distance(p *PeerAddress) (*math.Int, int) {
	var d PeerAddress
	for i := range d.addr {
		d.addr[i] = addr.addr[i] ^ p.addr[i]
	}
	r := math.NewIntFromBytes(d.addr[:])
	return r, numBuckets - r.BitLen()
}

//======================================================================
// Routing table implementation
//======================================================================

// RoutingTable holds the (local) routing table for a node.
// The index of of an address is the number of bits in the
// distance to the reference address, so smaller index means
// "nearer" to the reference address.
type RoutingTable struct {
	ref       *PeerAddress              // reference address for distance
	buckets   []*Bucket                 // list of buckets
	list      map[*PeerAddress]struct{} // keep list of peers
	rwlock    sync.RWMutex              // lock for write operations
	l2nse     float64                   // log2 of estimated network size
	inProcess bool                      // flag if Process() is running
}

// NewRoutingTable creates a new routing table for the reference address.
func NewRoutingTable(ref *PeerAddress) *RoutingTable {
	// create routing table
	rt := &RoutingTable{
		ref:       ref,
		list:      make(map[*PeerAddress]struct{}),
		buckets:   make([]*Bucket, numBuckets),
		l2nse:     0.,
		inProcess: false,
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
	// ensure one write and no readers
	rt.rwlock.Lock()
	defer rt.rwlock.Unlock()

	// check if peer is already known
	if _, ok := rt.list[p]; ok {
		return false
	}

	// compute distance (bucket index) and insert address.
	_, idx := p.Distance(rt.ref)
	if rt.buckets[idx].Add(p) {
		rt.list[p] = struct{}{}
		return true
	}
	// Full bucket: we did not add the address to the routing table.
	return false
}

// Remove peer address from routing table.
// Returns true if the entry was removed, false otherwise.
func (rt *RoutingTable) Remove(p *PeerAddress) bool {
	// ensure one write and no readers
	rt.rwlock.Lock()
	defer rt.rwlock.Unlock()

	// compute distance (bucket index) and remove entry from bucket
	_, idx := p.Distance(rt.ref)
	if rt.buckets[idx].Remove(p) {
		delete(rt.list, p)
		return true
	}
	// remove from internal list
	delete(rt.list, p)
	return false
}

//----------------------------------------------------------------------

// Process a function f in the locked context of a routing table
func (rt *RoutingTable) Process(f func() error) error {
	// ensure one write and no readers
	rt.rwlock.Lock()
	defer rt.rwlock.Unlock()
	return f()
}

//----------------------------------------------------------------------
// Routing functions
//----------------------------------------------------------------------

// SelectClosestPeer for a given peer address and bloomfilter.
func (rt *RoutingTable) SelectClosestPeer(p *PeerAddress, bf *PeerBloomFilter) (n *PeerAddress) {
	// no writer allowed
	rt.rwlock.RLock()
	defer rt.rwlock.RUnlock()

	// find closest address
	var dist *math.Int
	for _, b := range rt.buckets {
		if k, d := b.SelectClosestPeer(p, bf); n == nil || (d != nil && d.Cmp(dist) < 0) {
			dist = d
			n = k
		}
	}
	// mark peer as used
	n.lastUsed = util.AbsoluteTimeNow()
	return
}

// SelectRandomPeer returns a random address from table (that is not
// included in the bloomfilter)
func (rt *RoutingTable) SelectRandomPeer(bf *PeerBloomFilter) *PeerAddress {
	// no writer allowed
	rt.rwlock.RLock()
	defer rt.rwlock.RUnlock()

	// select random entry from list
	if size := len(rt.list); size > 0 {
		idx := rand.Intn(size)
		for k := range rt.list {
			if idx == 0 {
				// mark peer as used
				k.lastUsed = util.AbsoluteTimeNow()
				return k
			}
			idx--
		}
	}
	return nil
}

// SelectPeer selects a neighbor depending on the number of hops parameter.
// If hops < NSE this function MUST return SelectRandomPeer() and
// SelectClosestpeer() otherwise.
func (rt *RoutingTable) SelectPeer(p *PeerAddress, hops int, bf *PeerBloomFilter) *PeerAddress {
	if float64(hops) < rt.l2nse {
		return rt.SelectRandomPeer(bf)
	}
	return rt.SelectClosestPeer(p, bf)
}

// IsClosestPeer returns true if p is the closest peer for k. Peers with a
// positive test in the Bloom filter  are not considered.
func (rt *RoutingTable) IsClosestPeer(p, k *PeerAddress, bf *PeerBloomFilter) bool {
	n := rt.SelectClosestPeer(k, bf)
	return n.Equals(p)
}

// ComputeOutDegree computes the number of neighbors that a message should be forwarded to.
// The arguments are the desired replication level, the hop count of the message so far,
// and the base-2 logarithm of the current network size estimate (L2NSE) as provided by the
// underlay. The result is the non-negative number of next hops to select.
func (rt *RoutingTable) ComputeOutDegree(repl, hop int) int {
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
	timeout := util.NewRelativeTime(3 * time.Hour)
	if err := rt.Process(func() error {
		for addr := range rt.list {
			if addr.connected {
				continue
			}
			// check if we can/need to drop a peer
			drop := timeout.Compare(addr.lastSeen.Elapsed()) < 0
			if drop || timeout.Compare(addr.lastUsed.Elapsed()) < 0 {
				rt.Remove(addr)
			}
		}
		return nil
	}); err != nil {
		logger.Println(logger.ERROR, "[dht] RT heartbeat: "+err.Error())
	}
}

//======================================================================
// Routing table buckets
//======================================================================

// Bucket holds peer entries with approx. same distance from node
type Bucket struct {
	list   []*PeerAddress
	rwlock sync.RWMutex
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
	b.rwlock.Lock()
	defer b.rwlock.Unlock()

	// check for free space in bucket
	if len(b.list) < numK {
		// append entry at the end
		b.list = append(b.list, p)
		return true
	}
	return false
}

// Remove peer address from the bucket.
// Returns true if entry is removed (found), false otherwise.
func (b *Bucket) Remove(p *PeerAddress) bool {
	// only one writer and no readers
	b.rwlock.Lock()
	defer b.rwlock.Unlock()

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
func (b *Bucket) SelectClosestPeer(p *PeerAddress, bf *PeerBloomFilter) (n *PeerAddress, dist *math.Int) {
	// no writer allowed
	b.rwlock.RLock()
	defer b.rwlock.RUnlock()

	for _, addr := range b.list {
		// skip addresses in bloomfilter
		if bf.Contains(addr) {
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
