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

package filter

import (
	"bytes"
	"crypto/rand"
	"sort"
	"testing"
)

type Entry []byte

type EntryList []Entry

func (list EntryList) Len() int           { return len(list) }
func (list EntryList) Swap(i, j int)      { list[i], list[j] = list[j], list[i] }
func (list EntryList) Less(i, j int) bool { return bytes.Compare(list[i], list[j]) < 0 }

func (list EntryList) Contains(e Entry) bool {
	size := len(list)
	i := sort.Search(size, func(i int) bool { return bytes.Compare(list[i], e) >= 0 })
	return i != size
}

func TestBloomfilter(t *testing.T) {

	F := 500 // number of expected entries

	// The K-value for the HELLO_BF Bloom filter is always 16. The size S of
	// the Bloom filter in bytes depends on the number of elements F known to
	// be filtered at the initiator. If F is zero, the size S is just 8 (bytes).
	// Otherwise, S is set to the minimum of 2^15 and the lowest power of 2 that
	// is strictly larger than K*F/4 (in bytes). The wire format of HELLO_BF is
	// the resulting byte array. In particular, K is never transmitted.
	S := 1
	for S < 4*F && S < 32768 {
		S <<= 1
	}
	t.Logf("BloomFilter size in bytes: %d\n", S)

	// generate positives (entries in the set)
	positives := make(EntryList, F)
	for i := 0; i < F; i++ {
		data := make(Entry, 32)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		positives[i] = data
	}
	sort.Sort(positives)

	// generate negatives (entries outside the set)
	negatives := make(EntryList, F)
	for i := 0; i < F; {
		data := make(Entry, 32)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		if !positives.Contains(data) {
			negatives[i] = data
			i++
		}
	}

	// create BloomFilter
	bf := NewBloomFilter(S)

	// add positives to bloomfilter
	for _, e := range positives {
		bf.Add(e)
	}

	// check lookup of positives
	count := 0
	for _, e := range positives {
		if !bf.Contains(e) {
			count++
		}
	}
	if count > 0 {
		t.Logf("FAILED with %d false-negatives", count)
	}

	// check lookup of negatives
	count = 0
	for _, e := range negatives {
		if bf.Contains(e) {
			count++
		}
	}
	if count > 0 {
		t.Logf("FAILED with %d false-positives", count)
	}
}
