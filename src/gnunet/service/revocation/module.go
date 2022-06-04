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
	"context"
	"gnunet/config"
	"gnunet/core"
	"gnunet/crypto"
	"gnunet/message"
	"gnunet/service"
	"gnunet/util"
	"net/http"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

//======================================================================
// "GNUnet Revocation" implementation
//======================================================================

// The minimum average difficulty acceptable for a set of revocation PoWs
const MinAvgDifficulty = 23

// Module handles the revocation-related calls to other modules.
type Module struct {
	service.ModuleImpl

	bloomf *data.BloomFilter // bloomfilter for fast revocation check
	kvs    service.KVStore   // storage for known revocations
}

// NewModule returns an initialized revocation module
func NewModule(ctx context.Context, c *core.Core) (m *Module) {
	// create and init instance
	m = &Module{
		ModuleImpl: *service.NewModuleImpl(),
	}
	init := func() (err error) {
		// Initialize access to revocation data storage
		if m.kvs, err = service.NewKVStore(config.Cfg.Revocation.Storage); err != nil {
			return
		}
		// traverse the storage and build bloomfilter for all keys
		m.bloomf = data.NewBloomFilter(1000000, 1e-8)
		var keys []string
		if keys, err = m.kvs.List(); err != nil {
			return
		}
		for _, key := range keys {
			m.bloomf.Add([]byte(key))
		}
		return
	}
	if err := init(); err != nil {
		logger.Printf(logger.ERROR, "[revocation] Failed to initialize module: %s\n", err.Error())
		return nil
	}
	// register as listener for core events
	listener := m.Run(ctx, m.event, m.Filter(), 0, nil)
	c.Register("gns", listener)
	return m
}

//----------------------------------------------------------------------

// Filter returns the event filter for the service
func (m *Module) Filter() *core.EventFilter {
	f := core.NewEventFilter()
	f.AddMsgType(message.REVOCATION_QUERY)
	f.AddMsgType(message.REVOCATION_QUERY_RESPONSE)
	f.AddMsgType(message.REVOCATION_REVOKE)
	f.AddMsgType(message.REVOCATION_REVOKE_RESPONSE)
	return f
}

// Event handler
func (m *Module) event(ctx context.Context, ev *core.Event) {

}

//----------------------------------------------------------------------

// Query return true if the pkey is valid (not revoked) and false
// if the pkey has been revoked.
func (m *Module) Query(ctx context.Context, zkey *crypto.ZoneKey) (valid bool, err error) {
	// fast check first: is the key in the bloomfilter?
	data := zkey.Bytes()
	if !m.bloomf.Contains(data) {
		// no: it is valid (not revoked)
		return true, nil
	}
	// check in store to detect false-positives
	key := util.EncodeBinaryToString(data)
	if _, err = m.kvs.Get(key); err != nil {
		logger.Printf(logger.ERROR, "[revocation] Failed to locate key '%s' in store: %s\n", key, err.Error())
		// assume not revoked...
		return true, err
	}
	// key seems to be revoked
	return false, nil
}

// Revoke a key with given revocation data
func (m *Module) Revoke(ctx context.Context, rd *RevData) (success bool, err error) {
	// verify the revocation data
	diff, rc := rd.Verify(true)
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
	}
	if diff < float64(MinAvgDifficulty) {
		logger.Println(logger.WARN, "[revocation] Revoke: Difficulty to small")
		return false, nil
	}

	// store the revocation data
	// (1) add it to the bloomfilter
	m.bloomf.Add(rd.ZoneKeySig.KeyData)
	// (2) add it to the store
	var buf []byte
	if buf, err = data.Marshal(rd); err != nil {
		return false, err
	}
	value := util.EncodeBinaryToString(buf)
	err = m.kvs.Put(rd.ZoneKeySig.ID(), value)
	return true, err
}

//----------------------------------------------------------------------

// RPC returns the route and handler function for a JSON-RPC request
func (m *Module) RPC() (string, func(http.ResponseWriter, *http.Request)) {
	return "/revocation/", func(wrt http.ResponseWriter, req *http.Request) {
		wrt.Write([]byte(`{"msg": "This is REVOCATION" }`))
	}
}
