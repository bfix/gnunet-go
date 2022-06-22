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

package store

import (
	"encoding/hex"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/service/dht/blocks"
	"gnunet/util"
	"math/rand"
	"testing"
)

// test constants
const (
	fsNumBlocks = 40
)

// TestDHTFileStore generates 'fsNumBlocks' fully-random blocks
// and stores them under their SHA512 key. It than retrieves
// each block from storage and checks for matching hash.
func TestDHTFilesStore(t *testing.T) {

	// test configuration
	cfg := make(util.ParameterSet)
	cfg["mode"] = "file"
	cfg["cache"] = false
	cfg["path"] = "/var/lib/gnunet/dht/store"
	cfg["maxGB"] = 10

	// create file store
	fs, err := NewFileStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// allocate keys
	keys := make([]blocks.Query, 0, fsNumBlocks)

	// First round: save blocks
	for i := 0; i < fsNumBlocks; i++ {
		// generate random block
		size := 1024 + rand.Intn(62000)
		buf := make([]byte, size)
		rand.Read(buf)
		val := blocks.NewGenericBlock(buf)
		// generate associated key
		k := crypto.Hash(buf).Bits
		key := blocks.NewGenericQuery(k, enums.BLOCK_TYPE_ANY, 0)

		// store block
		if err := fs.Put(key, val); err != nil {
			t.Fatal(err)
		}
		// remember key
		keys = append(keys, key)
	}

	// Second round: retrieve blocks and check
	for _, key := range keys {
		// get block
		val, err := fs.Get(key)
		if err != nil {
			t.Fatal(err)
		}
		buf := val.Data()

		// re-create key
		k := crypto.Hash(buf)

		// do the keys match?
		if !k.Equals(key.Key()) {
			t.Log(hex.EncodeToString(k.Bits))
			t.Log(hex.EncodeToString(key.Key().Bits))
			t.Fatal("key/value mismatch")
		}
	}
}