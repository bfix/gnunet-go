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
	"errors"
	"gnunet/enums"
	"gnunet/service/dht/blocks"
	"gnunet/service/store"

	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/math"
)

// getHelloCache tries to find the requested HELLO block in the HELLO cache
func (m *Module) getHelloCache(label string, addr *PeerAddress, rf blocks.ResultFilter) (entry *store.DHTEntry, dist *math.Int) {
	logger.Printf(logger.DBG, "[%s] GET message for HELLO: check cache", label)
	// find best cached HELLO
	var block blocks.Block
	block, dist = m.rtable.BestHello(addr, rf)

	// if block is filtered, skip it
	if block != nil {
		if !rf.Contains(block) {
			entry = &store.DHTEntry{Blk: block}
		} else {
			logger.Printf(logger.DBG, "[%s] GET message for HELLO: matching DHT block is filtered", label)
			entry = nil
			dist = nil
		}
	}
	return
}

// getLocalStorage tries to find the requested block in local storage
func (m *Module) getLocalStorage(label string, query blocks.Query, rf blocks.ResultFilter) (entry *store.DHTEntry, dist *math.Int, err error) {

	// query DHT store for exact match  (9.4.3.3c)
	if entry, err = m.store.Get(query); err != nil {
		logger.Printf(logger.ERROR, "[%s] Failed to get DHT block from storage: %s", label, err.Error())
		return
	}
	if entry != nil {
		dist = math.ZERO
		// check if we are filtered out
		if rf.Contains(entry.Blk) {
			logger.Printf(logger.DBG, "[%s] matching DHT block is filtered", label)
			entry = nil
			dist = nil
		}
	}
	// if we have no exact match, find approximate block if requested
	if entry == nil || query.Flags()&enums.DHT_RO_FIND_APPROXIMATE != 0 {
		// no exact match: find approximate (9.4.3.3b)
		match := func(e *store.DHTEntry) bool {
			return rf.Contains(e.Blk)
		}
		var d any
		entry, d, err = m.store.GetApprox(query, match)
		var ok bool
		dist, ok = d.(*math.Int)
		if !ok {
			err = errors.New("no approx distance")
		}
		if err != nil {
			logger.Printf(logger.ERROR, "[%s] Failed to get (approx.) DHT block from storage: %s", label, err.Error())
		}
	}
	return
}
