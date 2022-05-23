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
	"gnunet/core"
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

// NewPeerAddress returns the DHT address of a peer
func NewPeerAddress(peer core.PeerID) *PeerAddress {
	r := new(PeerAddress)
	h := rtHash()
	h.Write(peer[:])
	copy(r.addr[:], h.Sum(nil))
	return r
}

func (addr *PeerAddress) String() string {
	return hex.EncodeToString(addr.addr[:])
}

func (addr *PeerAddress) Equals(p *PeerAddress) bool {
	return bytes.Compare(addr.addr[:], p.addr[:]) == 0
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
//======================================================================

// RT command codes:
const (
	RtcConnect    = iota // PEER_CONNECTED
	RtcDisconnect        // PEER_DISCONNECTED
)

// RTCommand is a command sent by the transport layer to keep the
// routing table up-to-date.
type RTCommand struct {
	Cmd  int          // command identifier ("Rtc???")
	Peer *PeerAddress // address of peer involved
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
					go rt.Add(cmd.Peer, true)

				// signal: peer disconnected
				case RtcDisconnect:
					go rt.Remove(cmd.Peer)
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

	// Full bucket: try to apply eviction strategy...

	// we did not add the address to the routing table
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
	rc := rt.buckets[idx].Remove(p)
	if rc {
		delete(rt.list, p)
	}
	return rc
}

//----------------------------------------------------------------------
// routing functions
//----------------------------------------------------------------------

// SelectClosestPeer for a given peer address and bloomfilter.
func (rt *RoutingTable) SelectClosestPeer(p *PeerAddress, bf *BloomFilter) (n *PeerAddress) {
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
func (rt *RoutingTable) SelectRandomPeer(bf *BloomFilter) (n *PeerAddress) {
	// no writer allowed
	rt.rwlock.RLock()
	defer rt.rwlock.RUnlock()

	// check for entries
	if size := len(rt.list); size > 0 {
		idx := rand.Intn(size)
		addrs := make([]*PeerAddress, 0, size)
		for k := range rt.list {
			addrs = append(addrs, k)
		}
		return addrs[idx]
	}
	return
}

//======================================================================
//======================================================================

// PeerEntry in a k-Bucket: use routing specific attributes
// for book-keeping
type PeerEntry struct {
	addr      *PeerAddress // peer address
	connected bool         // is peer connected?
}

//======================================================================
//======================================================================

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

func (b *Bucket) SelectClosestPeer(p *PeerAddress, bf *BloomFilter) (n *PeerAddress, dist *math.Int) {
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
