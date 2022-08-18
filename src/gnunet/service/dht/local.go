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
	"gnunet/enums"
	"gnunet/service/dht/blocks"
	"gnunet/service/store"

	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/math"
)

// lookupHelloCache tries to find the requested HELLO block in the HELLO cache
func (m *Module) lookupHelloCache(label string, addr *PeerAddress, rf blocks.ResultFilter, approx bool) (results []*store.DHTResult) {
	logger.Printf(logger.DBG, "[%s] GET message for HELLO: check cache", label)
	// find best cached HELLO
	return m.rtable.LookupHello(addr, rf, approx, label)
}

// getLocalStorage tries to find the requested block in local storage
func (m *Module) getLocalStorage(label string, query blocks.Query, rf blocks.ResultFilter) (results []*store.DHTResult, err error) {

	// query DHT store for exact matches  (9.4.3.3c)
	var entries []*store.DHTEntry
	if entries, err = m.store.Get(label, query, rf); err != nil {
		logger.Printf(logger.ERROR, "[%s] Failed to get DHT block from storage: %s", label, err.Error())
		return
	}
	for _, entry := range entries {
		// add entry to result list
		result := &store.DHTResult{
			Entry: entry,
			Dist:  math.ZERO,
		}
		results = append(results, result)
		// add to result filter
		rf.Add(entry.Blk)
	}
	// if we have no exact match, find approximate block if requested
	if len(results) == 0 || query.Flags()&enums.DHT_RO_FIND_APPROXIMATE != 0 {
		// no exact match: find approximate (9.4.3.3b)
		if results, err = m.store.GetApprox(label, query, rf); err != nil {
			logger.Printf(logger.ERROR, "[%s] Failed to get (approx.) DHT blocks from storage: %s", label, err.Error())
		}
	}
	return
}
