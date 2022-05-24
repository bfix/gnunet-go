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
	"encoding/hex"
	"fmt"
	"gnunet/crypto"
	"gnunet/message"
	"io/ioutil"
	"os"
	"strings"

	"github.com/bfix/gospel/data"
)

//------------------------------------------------------------
// Generic storage interface
//------------------------------------------------------------

// Store for DHT is a key/value storage where the type of the key is a SHA512
// hash result and value is a DHT block.
type Store interface {
	// Put block into storage under given key
	Put(key *crypto.HashCode, val *message.Block) error

	// Get block with given key from storage
	Get(key *crypto.HashCode) (*message.Block, error)
}

// NewStore creates a new storage handler with given spec
func NewStore(spec string) Store {
	split := strings.SplitN(spec, "+", 2)
	switch split[0] {
	case "file":
		return NewFileStore(split[1])
	}
	return nil
}

//------------------------------------------------------------
// Filesystem-based storage
//------------------------------------------------------------

// This implementation uses a simple filesystem-based storage mechanism
// for data.
type FileStore struct {
	path string // storage path
}

// NewFileStore instantiates a new file storage.
func NewFileStore(path string) *FileStore {
	return &FileStore{
		path: path,
	}
}

// Put block into storage under given key
func (s *FileStore) Put(key *crypto.HashCode, val *message.Block) (err error) {
	// get path and filename from key
	path, fname := s.expandPath(key)
	// make sure the path exists
	if err = os.MkdirAll(path, 0755); err != nil {
		return
	}
	// create file for storage
	var fp *os.File
	if fp, err = os.Create(path + "/" + fname); err == nil {
		defer fp.Close()
		var buf []byte
		if buf, err = data.Marshal(val); err == nil {
			// write block data
			_, err = fp.Write(buf)
		}
	}
	return
}

// Get block with given key from storage
func (s *FileStore) Get(key *crypto.HashCode) (val *message.Block, err error) {
	// get path and filename from key
	path, fname := s.expandPath(key)
	// read file content (block data)
	var buf []byte
	if buf, err = ioutil.ReadFile(path + "/" + fname); err != nil {
		return
	}
	// assemble Block object
	val = new(message.Block)
	err = data.Unmarshal(val, buf)
	return
}

// expandPath returns the full path to the file for given key.
func (s *FileStore) expandPath(key *crypto.HashCode) (string, string) {
	h := hex.EncodeToString(key.Bits)
	return fmt.Sprintf("%s/%s/%s", s.path, h[:2], h[2:4]), h[4:]
}
