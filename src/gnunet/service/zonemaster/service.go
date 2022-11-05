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
	var label string
	if v := ctx.Value(core.CtxKey("params")); v != nil {
		if ps, ok := v.(util.ParameterSet); ok {
			label, _ = util.GetParam[string](ps, "label")
		}
	}
	// perform lookup
	switch msg.(type) {

	//------------------------------------------------------------------
	// Identity service
	//------------------------------------------------------------------

	case *message.IdentityStartMsg,
		*message.IdentityCreateMsg,
		*message.IdentityRenameMsg,
		*message.IdentityDeleteMsg,
		*message.IdentityLookupMsg:
		zm.identity.HandleMessage(ctx, sender, msg, back)

	//------------------------------------------------------------------
	// Namestore service
	//------------------------------------------------------------------

	case *message.NamestoreZoneIterStartMsg,
		*message.NamestoreZoneIterNextMsg,
		*message.NamestoreRecordStoreMsg,
		*message.NamestoreRecordLookupMsg,
		*message.NamestoreZoneToNameMsg,
		*message.NamestoreZoneToNameRespMsg,
		*message.NamestoreMonitorStartMsg,
		*message.NamestoreMonitorNextMsg:
		zm.namestore.HandleMessage(ctx, sender, msg, back)

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
