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
	"gnunet/message"
	"gnunet/service"
	"gnunet/service/dht/blocks"
	"gnunet/service/store"
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
func (zm *ZoneMaster) HandleMessage(ctx context.Context, sender *util.PeerID, msg message.Message, back transport.Responder) bool {
	// assemble log label
	var id int
	var label string
	if v := ctx.Value("params"); v != nil {
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
	case *message.IdentityStartMsg:
		// flag client as update receiver
		zm.identity.FollowUpdates(id)
		// initial update is to send all existing identites
		var err error
		var list []*store.Identity
		if list, err = zm.zdb.GetIdentities(""); err != nil {
			logger.Printf(logger.ERROR, "[zonemaster%s] %s", label, err.Error())
			return false

		}
		for _, ident := range list {
			resp := message.NewIdentityUpdateMsg(ident.Name, ident.Key)
			logger.Printf(logger.DBG, "[zonemaster%s] Sending %v", label, resp)
			if err = back.Send(ctx, resp); err != nil {
				logger.Printf(logger.ERROR, "[zonemaster%s] Can't send response (%v): %v\n", label, resp, err)
				return false
			}
		}
		// terminate with EOL
		resp := message.NewIdentityUpdateMsg("", nil)
		if err = back.Send(ctx, resp); err != nil {
			logger.Printf(logger.ERROR, "[zonemaster%s] Can't send response (%v): %v\n", label, resp, err)
			return false
		}

		/*
			resp := message.NewIdentityResultCodeMsg(enums.RC_OK, "")
			if err := back.Send(ctx, resp); err != nil {
				logger.Printf(logger.ERROR, "[zonemaster%s] Can't send response (%v)\n", label, resp)
				return false
			}
		*/

	//------------------------------------------------------------------
	// Namestore service
	//------------------------------------------------------------------

	// start new zone iteration
	case *message.NamestoreZoneIterStartMsg:
		iter := zm.namestore.NewIterator(m.ID, m.ZoneKey)
		resp := iter.Next()
		if err := back.Send(ctx, resp); err != nil {
			logger.Printf(logger.ERROR, "[zonemaster%s] Can't send response (%v)\n", label, resp)
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