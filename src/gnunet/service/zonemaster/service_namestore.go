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

package zonemaster

import (
	"gnunet/crypto"
	"gnunet/message"
	"gnunet/service/store"
	"gnunet/util"
)

//----------------------------------------------------------------------
// "GNUnet Namestore" service implementation:
//----------------------------------------------------------------------

type ZoneIterator struct {
	id       uint32
	zk       *crypto.ZonePrivate
	lastUsed util.AbsoluteTime
	db       *store.ZoneDB

	labels []int64
	pos    int
}

func NewZoneIterator(id uint32, zk *crypto.ZonePrivate, db *store.ZoneDB) (zi *ZoneIterator, err error) {
	// get list of labels to handle
	var labels []int64
	if labels, err = db.GetLabelIDs(zk); err != nil {
		return
	}
	// assemble zone iterator
	zi = &ZoneIterator{
		id:       id,
		zk:       zk,
		lastUsed: util.AbsoluteTimeNow(),
		db:       db,
		pos:      0,
		labels:   labels,
	}
	return
}

func (zi *ZoneIterator) Next() *message.NamestoreRecordResultMsg {
	if zi.pos == len(zi.labels)-1 {
		// end of list reached
	}

	return nil
}

// NamestoreService to handle namestore requests
type NamestoreService struct {
	iters *util.Map[uint32, *ZoneIterator]
}

func NewNamestoreService() *NamestoreService {
	return &NamestoreService{
		iters: util.NewMap[uint32, *ZoneIterator](),
	}
}

func (s *NamestoreService) NewIterator(id uint32, zk *crypto.ZonePrivate) *ZoneIterator {
	zi := &ZoneIterator{
		id:       id,
		zk:       zk,
		lastUsed: util.AbsoluteTimeNow(),
	}
	s.iters.Put(id, zi, 0)
	return zi
}
