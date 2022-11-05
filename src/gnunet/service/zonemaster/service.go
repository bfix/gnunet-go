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
	"fmt"
	"io"

	"gnunet/config"
	"gnunet/core"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service"
	"gnunet/service/dht/blocks"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// "GNUnet Zonemaster" socket service implementation:
// Zonemaster handles Namestore and Identity messages.
//----------------------------------------------------------------------

// ServeClient processes a client channel.
func (zm *ZoneMaster) ServeClient(ctx context.Context, id int, mc *service.Connection) {
	reqID := 0
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)

	// inform sub-service about new session
	zm.identity.NewSession(id, mc)

	for {
		// receive next message from client
		reqID++
		logger.Printf(logger.DBG, "[zonemaster:%d:%d] Waiting for client request...\n", id, reqID)
		msg, err := mc.Receive(ctx)
		if err != nil {
			if err == io.EOF {
				logger.Printf(logger.INFO, "[zonemaster:%d:%d] Client channel closed.\n", id, reqID)
			} else if err == service.ErrConnectionInterrupted {
				logger.Printf(logger.INFO, "[zonemaster:%d:%d] Service operation interrupted.\n", id, reqID)
			} else {
				logger.Printf(logger.ERROR, "[zonemaster:%d:%d] Message-receive failed: %s\n", id, reqID, err.Error())
			}
			break
		}
		logger.Printf(logger.INFO, "[zonemaster:%d:%d] Received request: %v\n", id, reqID, msg)

		// context with values
		values := make(util.ParameterSet)
		values["id"] = id
		values["label"] = fmt.Sprintf(":%d:%d", id, reqID)
		valueCtx := context.WithValue(ctx, core.CtxKey("params"), values)

		// handle message
		zm.HandleMessage(valueCtx, nil, msg, mc)
	}
	// inform sub.services about closed session
	zm.identity.CloseSession(id)

	// close client connection
	mc.Close()

	// cancel all tasks running for this session/connection
	logger.Printf(logger.INFO, "[zonemaster:%d] Closing session...\n", id)
	cancel()
}

// Handle a single incoming message
//
//nolint:gocyclo // life is complex sometimes...
func (zm *ZoneMaster) HandleMessage(ctx context.Context, sender *util.PeerID, msg message.Message, back transport.Responder) bool {
	// assemble log label
	var id int
	var label string
	if v := ctx.Value(core.CtxKey("params")); v != nil {
		if ps, ok := v.(util.ParameterSet); ok {
			label, _ = util.GetParam[string](ps, "label")
			id, _ = util.GetParam[int](ps, "id")
		}
	}
	// perform lookup
	switch m := msg.(type) {

	//------------------------------------------------------------------
	// Identity service
	//------------------------------------------------------------------

	// start identity update listener
	case *message.IdentityStartMsg:
		if err := zm.identity.Start(ctx, id); err != nil {
			logger.Printf(logger.ERROR, "[identity%s] Identity session for %d failed: %v\n", label, id, err)
			return false
		}

	// create a new identity with given private key
	case *message.IdentityCreateMsg:
		if err := zm.identity.Create(ctx, id, m.ZoneKey, m.Name()); err != nil {
			logger.Printf(logger.ERROR, "[identity%s] Identity create failed: %v\n", label, err)
			return false
		}

	// rename identity
	case *message.IdentityRenameMsg:
		id, err := zm.zdb.GetZoneByName(m.OldName())
		if err != nil {
			logger.Printf(logger.ERROR, "[identity%s] Identity lookup failed: %v\n", label, err)
			return false
		}
		// change name
		id.Name = m.NewName()
		err = zm.zdb.SetZone(id)

		// send response
		rc := 0
		if err != nil {
			rc = 1
		}
		resp := message.NewIdentityResultCodeMsg(rc)
		if !sendResponse(ctx, "identity"+label, resp, back) {
			return false
		}

	// delete identity
	case *message.IdentityDeleteMsg:
		id, err := zm.zdb.GetZoneByName(m.Name())
		if err != nil {
			logger.Printf(logger.ERROR, "[identity%s] Identity lookup failed: %v\n", label, err)
			return false
		}
		// delete in database
		id.Name = ""
		err = zm.zdb.SetZone(id)

		// send response
		rc := 0
		if err != nil {
			rc = 1
		}
		resp := message.NewIdentityResultCodeMsg(rc)
		if !sendResponse(ctx, "identity"+label, resp, back) {
			return false
		}

	// lookup identity
	case *message.IdentityLookupMsg:
		id, err := zm.zdb.GetZoneByName(m.Name)
		if err != nil {
			logger.Printf(logger.ERROR, "[identity%s] Identity lookup failed: %v\n", label, err)
			return false
		}
		resp := message.NewIdentityUpdateMsg(id.Name, id.Key)
		if !sendResponse(ctx, "identity"+label, resp, back) {
			return false
		}

	//------------------------------------------------------------------
	// Namestore service
	//------------------------------------------------------------------

	// start new zone iteration
	case *message.NamestoreZoneIterStartMsg:
		// setup iterator
		iter := zm.namestore.NewIterator(m.ID, m.ZoneKey)
		// return first result
		resp, done := iter.Next()
		if done {
			zm.namestore.DropIterator(m.ID)
		}
		if !sendResponse(ctx, "namestore"+label, resp, back) {
			return false
		}

	// next label(s) from zone iteration
	case *message.NamestoreZoneIterNextMsg:
		var resp message.Message
		// lookup zone iterator
		iter, ok := zm.namestore.GetIterator(m.ID)
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
					zm.namestore.DropIterator(m.ID)
					break
				}
			}
		}

	// store record in zone database
	case *message.NamestoreRecordStoreMsg:
		var rc uint32
		if !zm.namestore.Store(m.ZoneKey, m.RSets) {
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
			zone, err := zm.zdb.GetZoneByKey(m.ZoneKey)
			if err != nil {
				logger.Printf(logger.ERROR, "[namestore%s] zone lookup: %s", label, err.Error())
				return nil
			}
			lbl, err := zm.zdb.GetLabelByName(string(m.Label), zone.ID, false)
			if err != nil {
				logger.Printf(logger.ERROR, "[namestore%s] label lookup: %s", label, err.Error())
				return nil
			}
			rrSet, _, err := zm.GetRecordSet(lbl.ID, enums.GNSFilter(m.Filter))
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

	default:
		//----------------------------------------------------------
		// UNKNOWN message type received
		//----------------------------------------------------------
		logger.Printf(logger.ERROR, "[zonemaster%s] Unhandled message of type (%s)\n", label, msg.Type())
		return false
	}
	return true
}

// storeDHT stores a GNS block in the DHT.
func (zm *ZoneMaster) StoreDHT(ctx context.Context, query blocks.Query, block blocks.Block) (err error) {
	// assemble DHT request
	req := message.NewDHTP2PPutMsg(block)
	req.Flags = query.Flags()
	req.Key = query.Key().Clone()

	// store block
	_, err = service.RequestResponse(ctx, "zonemaster", "dht", config.Cfg.DHT.Service.Socket, req, false)
	return
}

// storeNamecache stores a GNS block in the local namecache.
func (zm *ZoneMaster) StoreNamecache(ctx context.Context, query *blocks.GNSQuery, block *blocks.GNSBlock) (err error) {
	// assemble Namecache request
	req := message.NewNamecacheCacheMsg(block)

	// get response from Namecache service
	_, err = service.RequestResponse(ctx, "zonemaster", "namecache", config.Cfg.Namecache.Service.Socket, req, false)
	return
}

func sendResponse(ctx context.Context, label string, resp message.Message, back transport.Responder) bool {
	logger.Printf(logger.DBG, "[%s] Sending %v", label, resp)
	if err := back.Send(ctx, resp); err != nil {
		logger.Printf(logger.ERROR, "[%s] Can't send response (%v)\n", label, resp)
		return false
	}
	return true
}
