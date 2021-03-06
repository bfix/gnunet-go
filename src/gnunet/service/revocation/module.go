// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
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

package revocation

import (
	"gnunet/config"
	"gnunet/service"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

//======================================================================
// "GNUnet Revocation" implementation
//======================================================================

// RevocationModule handles the revocation-related calls to other modules.
type RevocationModule struct {
	bloomf *data.BloomFilter  // bloomfilter for fast revocation check
	kvs    util.KeyValueStore // storage for known revocations
}

// Init a revocation module
func (m *RevocationModule) Init() error {
	// Initialize access to revocation data storage
	var err error
	if m.kvs, err = util.OpenKVStore(config.Cfg.Revocation.Storage); err != nil {
		return err
	}
	// traverse the storage and build bloomfilter for all keys
	m.bloomf = data.NewBloomFilter(1000000, 1e-8)
	keys, err := m.kvs.List()
	if err != nil {
		return err
	}
	for _, key := range keys {
		buf, err := util.DecodeStringToBinary(key, 32)
		if err != nil {
			return err
		}
		m.bloomf.Add(buf)
	}
	return nil
}

// NewRevocationModule returns an initialized revocation module
func NewRevocationModule() *RevocationModule {
	m := new(RevocationModule)
	if err := m.Init(); err != nil {
		logger.Printf(logger.ERROR, "[revocation] Failed to initialize module: %s\n", err.Error())
		return nil
	}
	return m
}

// Query return true if the pkey is valid (not revoked) and false
// if the pkey has been revoked.
func (s *RevocationModule) Query(ctx *service.SessionContext, pkey *ed25519.PublicKey) (valid bool, err error) {
	// fast check first: is the key in the bloomfilter?
	data := pkey.Bytes()
	if !s.bloomf.Contains(data) {
		// no: it is valid (not revoked)
		return true, nil
	}
	// check in store to detect false-positives
	key := util.EncodeBinaryToString(data)
	if _, err = s.kvs.Get(key); err != nil {
		logger.Printf(logger.ERROR, "[revocation] Failed to locate key '%s' in store: %s\n", key, err.Error())
		// assume not revoked...
		return true, err
	}
	// key seems to be revoked
	return false, nil
}

// Revoke
func (s *RevocationModule) Revoke(ctx *service.SessionContext, rd *RevData) (success bool, err error) {
	// verify the revocation data
	rc := rd.Verify(true)
	switch {
	case rc == -1:
		logger.Println(logger.WARN, "[revocation] Revoke: Missing/invalid signature")
		return false, nil
	case rc == -2:
		logger.Println(logger.WARN, "[revocation] Revoke: Expired revocation")
		return false, nil
	case rc == -3:
		logger.Println(logger.WARN, "[revocation] Revoke: Wrong PoW sequence order")
		return false, nil
	case rc < 25:
		logger.Println(logger.WARN, "[revocation] Revoke: Difficulty to small")
		return false, nil
	}
	// store the revocation data
	// (1) add it to the bloomfilter
	s.bloomf.Add(rd.ZoneKey)
	// (2) add it to the store
	var buf []byte
	key := util.EncodeBinaryToString(rd.ZoneKey)
	if buf, err = data.Marshal(rd); err != nil {
		return false, err
	}
	value := util.EncodeBinaryToString(buf)
	err = s.kvs.Put(key, value)
	return true, err
}
