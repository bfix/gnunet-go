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
	"context"
	"gnunet/core"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service/dht/blocks"
	"gnunet/service/store"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
)

//======================================================================
// "GNUnet Namestore" service implementation:
//======================================================================

//----------------------------------------------------------------------
// Zone iterator
//----------------------------------------------------------------------

// ZoneIterator is used to traverse all labels in a zone
type ZoneIterator struct {
	id       uint32              // request ID
	zid      int64               // database ID of zone
	zk       *crypto.ZonePrivate // private zone key
	lastUsed util.AbsoluteTime   // last time iterator was used
	zm       *ZoneMaster         // reference to zone master
	labels   []int64             // list of label ids in database for zone
	pos      int                 // iteration step
}

// NewZoneIterator initialize an iterator to traverse the zone labels
func NewZoneIterator(id uint32, zk *crypto.ZonePrivate, zm *ZoneMaster) (zi *ZoneIterator, err error) {
	// get list of labels to handle
	var labels []int64
	var zid int64
	if labels, zid, err = zm.zdb.GetLabelIDs(zk); err != nil {
		return
	}
	// assemble zone iterator
	zi = &ZoneIterator{
		id:       id,
		zid:      zid,
		zk:       zk,
		lastUsed: util.AbsoluteTimeNow(),
		zm:       zm,
		pos:      0,
		labels:   labels,
	}
	return
}

// Next returns the next record
func (zi *ZoneIterator) Next() (msg message.Message, done bool) {
	if zi.pos == len(zi.labels) {
		// end of list reached:
		msg = message.NewNamestoreZoneIterEndMsg(zi.id)
		done = true
		return
	}
	// get resource records
	lid := zi.labels[zi.pos]
	zi.pos++
	lbl, err := zi.zm.zdb.GetLabel(lid)
	if err != nil {
		logger.Printf(logger.ERROR, "[zone_iter] label name: %s", err.Error())
		return
	}
	rrSet, expire, err := zi.zm.GetRecordSet(lid, enums.GNS_FILTER_NONE)
	if err != nil {
		logger.Printf(logger.ERROR, "[zone_iter] records: %s", err.Error())
		return
	}
	// assemble response
	rmsg := message.NewNamestoreRecordResultMsg(zi.id, zi.zk, lbl.Name)
	rmsg.Expire = expire
	rmsg.AddRecords(rrSet)
	msg = rmsg
	return
}

//----------------------------------------------------------------------
// Namestore service
//----------------------------------------------------------------------

// NamestoreService to handle namestore requests
type NamestoreService struct {
	zm    *ZoneMaster
	iters *util.Map[uint32, *ZoneIterator]
}

// NewNamestoreService creates a new namestore service handler
func NewNamestoreService(zm *ZoneMaster) *NamestoreService {
	return &NamestoreService{
		zm:    zm,
		iters: util.NewMap[uint32, *ZoneIterator](),
	}
}

// NewIterator creates a new iterator for zone traversal
func (s *NamestoreService) NewIterator(id uint32, zk *crypto.ZonePrivate) *ZoneIterator {
	zi, err := NewZoneIterator(id, zk, s.zm)
	if err != nil {
		logger.Printf(logger.ERROR, "[namestore] new zone iterator: %s", err.Error())
		return nil
	}
	s.iters.Put(id, zi, 0)
	return zi
}

// GetIterator returns the iterator for request ID
func (s *NamestoreService) GetIterator(id uint32) (*ZoneIterator, bool) {
	return s.iters.Get(id, 0)
}

// DropIterator removes the iterator for request ID
func (s *NamestoreService) DropIterator(id uint32) {
	s.iters.Delete(id, 0)
}

// Store labeled recordsets to zone
func (s *NamestoreService) Store(zk *crypto.ZonePrivate, list []*message.NamestoreRecordSet) bool {
	// get the zone with given key
	zone, err := s.zm.zdb.GetZoneByKey(zk)
	if err != nil {
		logger.Printf(logger.ERROR, "[namestore] zone from key: %s", err.Error())
		return false
	}
	// add all record sets
	for _, entry := range list {
		// get labeled resource records
		label, _ := util.ReadCString(entry.Name, 0)
		// get label object from database
		var lbl *store.Label
		if lbl, err = s.zm.zdb.GetLabelByName(label, zone.ID, true); err != nil {
			logger.Printf(logger.ERROR, "[namestore] label from name: %s", err.Error())
			return false
		}
		// disassemble record set data
		rr, err := blocks.NewRecordSetFromRDATA(uint32(entry.RdCount), entry.RecData)
		if err != nil {
			logger.Printf(logger.ERROR, "[namestore] record from data: %s", err.Error())
			return false
		}
		for _, rr := range rr.Records {
			// assemble record and store in database
			rec := store.NewRecord(rr.Expire, rr.RType, rr.Flags, rr.Data)
			rec.Label = lbl.ID
			if err = s.zm.zdb.SetRecord(rec); err != nil {
				logger.Printf(logger.ERROR, "[namestore] add record: %s", err.Error())
				return false
			}
		}
	}
	return true
}

// HandleMessage processes a single incoming message
func (s *NamestoreService) HandleMessage(ctx context.Context, sender *util.PeerID, msg message.Message, back transport.Responder) bool {
	// assemble log label
	var label string
	if v := ctx.Value(core.CtxKey("params")); v != nil {
		if ps, ok := v.(util.ParameterSet); ok {
			label, _ = util.GetParam[string](ps, "label")
		}
	}
	// perform lookup
	switch m := msg.(type) {

	// start new zone iteration
	case *message.NamestoreZoneIterStartMsg:
		// setup iterator
		iter := s.NewIterator(m.ID, m.ZoneKey)
		// return first result
		resp, done := iter.Next()
		if done {
			s.DropIterator(m.ID)
		}
		if !sendResponse(ctx, "namestore"+label, resp, back) {
			return false
		}

	// next label(s) from zone iteration
	case *message.NamestoreZoneIterNextMsg:
		var resp message.Message
		// lookup zone iterator
		iter, ok := s.GetIterator(m.ID)
		if !ok {
			zk, _ := crypto.NullZonePrivate(enums.GNS_TYPE_PKEY)
			resp = message.NewNamestoreRecordResultMsg(m.ID, zk, "")
			if !sendResponse(ctx, "namestore"+label, resp, back) {
				return false
			}
		} else {
			for n := 0; n < int(m.Limit); n++ {
				// return next result
				var done bool
				resp, done = iter.Next()
				if !sendResponse(ctx, "namestore"+label, resp, back) {
					return false
				}
				if done {
					s.DropIterator(m.ID)
					break
				}
			}
		}

	// store record in zone database
	case *message.NamestoreRecordStoreMsg:
		var rc uint32
		if !s.Store(m.ZoneKey, m.RSets) {
			rc = 1
		}
		resp := message.NewNamestoreRecordStoreRespMsg(m.ID, rc)
		if !sendResponse(ctx, "namestore"+label, resp, back) {
			return false
		}

	// lookup records in zone under given label
	case *message.NamestoreRecordLookupMsg:
		// get resource records
		getRecs := func() *blocks.RecordSet {
			zone, err := s.zm.zdb.GetZoneByKey(m.ZoneKey)
			if err != nil {
				logger.Printf(logger.ERROR, "[namestore%s] zone lookup: %s", label, err.Error())
				return nil
			}
			lbl, err := s.zm.zdb.GetLabelByName(string(m.Label), zone.ID, false)
			if err != nil {
				logger.Printf(logger.ERROR, "[namestore%s] label lookup: %s", label, err.Error())
				return nil
			}
			rrSet, _, err := s.zm.GetRecordSet(lbl.ID, enums.GNSFilter(m.Filter))
			if err != nil {
				logger.Printf(logger.ERROR, "[namestore%s] records: %s", label, err.Error())
				return nil
			}
			return rrSet
		}
		recs := getRecs()
		// assemble response
		resp := message.NewNamestoreRecordLookupRespMsg(m.ID, m.ZoneKey, string(m.Label))
		if recs != nil {
			resp.AddRecords(recs)
			resp.Found = 1
		}
		if !sendResponse(ctx, "namestore"+label, resp, back) {
			return false
		}

	case *message.NamestoreZoneToNameMsg:

	}
	return true
}
