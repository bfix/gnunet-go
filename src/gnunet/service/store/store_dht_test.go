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
	"os"
	"testing"
)

// test constants
const (
	fsNumBlocks = 10
)

// TestDHTFileStore generates 'fsNumBlocks' fully-random blocks
// and stores them under their SHA512 key. It than retrieves
// each block from storage and checks for matching hash.
func TestDHTFilesStore(t *testing.T) {
	// test configuration
	path := "/tmp/dht-store"
	defer func() {
		os.RemoveAll(path)
	}()

	cfg := make(util.ParameterSet)
	cfg["mode"] = "file"
	cfg["cache"] = false
	cfg["path"] = path
	cfg["maxGB"] = 10

	// create file store
	if _, err := os.Stat(path); err != nil {
		if err = os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	fs, err := NewDHTStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// allocate keys
	keys := make([]blocks.Query, 0, fsNumBlocks)
	// create result filter
	rf := blocks.NewGenericResultFilter()

	// First round: save blocks
	btype := enums.BLOCK_TYPE_TEST
	expire := util.AbsoluteTimeNever()
	for i := 0; i < fsNumBlocks; i++ {
		// generate random block
		size := 1024 + rand.Intn(62000) //nolint:gosec // good enough for testing
		buf := make([]byte, size)
		if _, err = rand.Read(buf); err != nil { //nolint:gosec // good enough for testing
			t.Fatal(err)
		}
		var blk blocks.Block
		if blk, err = blocks.NewBlock(btype, expire, buf); err != nil {
			t.Fatal(err)
		}
		// generate associated key
		k := crypto.Hash(buf)
		key := blocks.NewGenericQuery(k, enums.BLOCK_TYPE_TEST, 0)

		// store entry
		val := &DHTEntry{
			Blk: blk,
		}
		if err := fs.Put(key, val); err != nil {
			t.Fatalf("[%d] %s", i, err)
		}
		// remember key
		keys = append(keys, key)
	}

	// Second round: retrieve blocks and check
	for i, key := range keys {
		// get block
		vals, err := fs.Get("test", key, rf)
		if err != nil {
			t.Fatalf("[%d] %s", i, err)
		}
		if len(vals) != 1 {
			t.Fatalf("[%d] only one result expected", i)
		}
		buf := vals[0].Blk.Bytes()

		// re-create key
		k := crypto.Hash(buf)

		// do the keys match?
		if !k.Equal(key.Key()) {
			t.Log(hex.EncodeToString(k.Data))
			t.Log(hex.EncodeToString(key.Key().Data))
			t.Fatal("key/value mismatch")
		}
	}
}

func TestDHTEntryStore(t *testing.T) {
	// pth, sender, local := path.GenerateTestPath(10)
}
