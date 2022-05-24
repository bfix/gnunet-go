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
	addr [sizeAddr]byte
}

// NewPeerAddress returns the DHT address of a peer.
func NewPeerAddress(peer *util.PeerID) *PeerAddress {
	r := new(PeerAddress)
	h := rtHash()
	h.Write(peer.Key)
	copy(r.addr[:], h.Sum(nil))
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

// RT command codes:
const (
	RtcConnect    = iota // PEER_CONNECTED
	RtcDisconnect        // PEER_DISCONNECTED
	RtcL2NSE             // new network size estimation (log2) available
)

// RTCommand is a command sent by the transport layer to keep the
// routing table up-to-date.
type RTCommand struct {
	Cmd  int         // command identifier ("Rtc???")
	Data interface{} // command parameter
}

// RoutingTable holds the (local) routing table for a node.
// The index of of an address is the number of bits in the
// distance to the reference address, so smaller index means
// "nearer" to the reference address.
type RoutingTable struct {
	ref     *PeerAddress          // reference address for distance
	buckets []*Bucket             // list of buckets
	list    map[*PeerAddress]bool // keep list of peers
	rwlock  sync.RWMutex          // lock for write operations
	l2nse   float64               // log2 of estimated network size
}

// NewRoutingTable creates a new routing table for the reference address.
func NewRoutingTable(ref *PeerAddress) *RoutingTable {
	rt := new(RoutingTable)
	rt.ref = ref
	rt.list = make(map[*PeerAddress]bool)
	rt.buckets = make([]*Bucket, numBuckets)
	for i := range rt.buckets {
		rt.buckets[i] = NewBucket(numK)
	}
	return rt
}

// Run routing table command handler (used by the transport layer).
func (rt *RoutingTable) Run(ctx context.Context) chan *RTCommand {
	ch := make(chan *RTCommand)
	go func() {
		for {
			select {
			case cmd := <-ch:
				switch cmd.Cmd {
				// signal: peer connected
				case RtcConnect:
					// add peer to routing table
					go rt.Add(cmd.Data.(*PeerAddress), true)

				// signal: peer disconnected
				case RtcDisconnect:
					go rt.Remove(cmd.Data.(*PeerAddress))

				// signal: new NSE available
				case RtcL2NSE:
					rt.l2nse = cmd.Data.(float64)
				}
			// terminate signal received
			case <-ctx.Done():
				// quit command processing
				return
			}
		}
	}()
	return ch
}

// Add new peer address to routing table.
// Returns true if the entry was added, false otherwise.
func (rt *RoutingTable) Add(p *PeerAddress, connected bool) bool {
	// ensure one write and no readers
	rt.rwlock.Lock()
	defer rt.rwlock.Unlock()

	// compute distance (bucket index) and insert address.
	_, idx := p.Distance(rt.ref)
	if rt.buckets[idx].Add(p, connected) {
		rt.list[p] = true
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
	return false
}

//----------------------------------------------------------------------
// routing functions
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

//======================================================================
// Routing table buckets
//======================================================================

// PeerEntry in a k-Bucket: use routing specific attributes
// for book-keeping
type PeerEntry struct {
	addr      *PeerAddress // peer address
	connected bool         // is peer connected?
}

// Bucket holds peer entries with approx. same distance from node
type Bucket struct {
	list   []*PeerEntry
	rwlock sync.RWMutex
}

// NewBucket creates a new entry list of given size
func NewBucket(n int) *Bucket {
	return &Bucket{
		list: make([]*PeerEntry, 0, n),
	}
}

// Add peer address to the bucket if there is free space.
// Returns true if entry is added, false otherwise.
func (b *Bucket) Add(p *PeerAddress, connected bool) bool {
	// only one writer and no readers
	b.rwlock.Lock()
	defer b.rwlock.Unlock()

	// check for free space in bucket
	if len(b.list) < numK {
		// append entry at the end
		pe := &PeerEntry{
			addr:      p,
			connected: connected,
		}
		b.list = append(b.list, pe)
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
		if pe.addr.Equals(p) {
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

	for _, pe := range b.list {
		// skip addresses in bloomfilter
		if bf.Contains(pe.addr) {
			continue
		}
		// check for shorter distance
		if d, _ := p.Distance(pe.addr); n == nil || d.Cmp(dist) < 0 {
			// remember best match
			dist = d
			n = pe.addr
		}
	}
	return
}
