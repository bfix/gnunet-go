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
	"gnunet/message"
	"gnunet/service"
	"gnunet/service/dht/blocks"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
)

type ZoneIterator struct {
	zk *crypto.ZonePrivate
}

//----------------------------------------------------------------------
// "GNUnet Zonemaster" service implementation:
// The zonemaster service handles Namestore messages
//----------------------------------------------------------------------

// Service implements a GNS service
type Service struct {
	Module

	ZoneIters *util.Map[uint32, *ZoneIterator]
}

// NewService creates a new GNS service instance
func NewService(ctx context.Context, c *core.Core) service.Service {
	// instantiate service
	mod := NewModule(ctx, c)
	srv := &Service{
		Module:    *mod,
		ZoneIters: util.NewMap[uint32, *ZoneIterator](),
	}
	// set external function references (external services)
	srv.StoreLocal = srv.StoreNamecache
	srv.StoreRemote = srv.StoreDHT

	return srv
}

// ServeClient processes a client channel.
func (s *Service) ServeClient(ctx context.Context, id int, mc *service.Connection) {
	reqID := 0
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)

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

		// handle message
		valueCtx := context.WithValue(ctx, core.CtxKey("label"), fmt.Sprintf(":%d:%d", id, reqID))
		s.HandleMessage(valueCtx, nil, msg, mc)
	}
	// close client connection
	mc.Close()

	// cancel all tasks running for this session/connection
	logger.Printf(logger.INFO, "[zonemaster:%d] Start closing session...\n", id)
	cancel()
}

// Handle a single incoming message
func (s *Service) HandleMessage(ctx context.Context, sender *util.PeerID, msg message.Message, back transport.Responder) bool {
	// assemble log label
	label := ""
	if v := ctx.Value("label"); v != nil {
		label, _ = v.(string)
	}
	// perform lookup
	switch m := msg.(type) {

	// start new zone iteration
	case *message.NamestoreZoneIterStartMsg:
		zi := new(ZoneIterator)
		zi.zk = m.ZoneKey
		s.ZoneIters.Put(m.ID, zi, 0)

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
func (s *Service) StoreDHT(ctx context.Context, query blocks.Query, block blocks.Block) (err error) {
	// assemble DHT request
	req := message.NewDHTP2PPutMsg(block)
	req.Flags = query.Flags()
	req.Key = query.Key().Clone()

	// store block
	_, err = service.RequestResponse(ctx, "zonemaster", "dht", config.Cfg.DHT.Service.Socket, req, false)
	return
}

// storeNamecache stores a GNS block in the local namecache.
func (s *Service) StoreNamecache(ctx context.Context, query *blocks.GNSQuery, block *blocks.GNSBlock) (err error) {
	// assemble Namecache request
	req := message.NewNamecacheCacheMsg(block)

	// get response from Namecache service
	_, err = service.RequestResponse(ctx, "zonemaster", "namecache", config.Cfg.Namecache.Service.Socket, req, false)
	return
}
