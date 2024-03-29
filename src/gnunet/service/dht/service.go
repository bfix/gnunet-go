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
	"context"
	"fmt"
	"io"
	"time"

	"gnunet/config"
	"gnunet/core"
	"gnunet/service"

	"github.com/bfix/gospel/logger"
)

// Error codes
var (
	ErrInvalidID           = fmt.Errorf("invalid/unassociated ID")
	ErrBlockExpired        = fmt.Errorf("block expired")
	ErrInvalidResponseType = fmt.Errorf("invald response type")
)

// Time constants
var (
	DefaultGetTTL   = 10 * time.Minute // timeout for GET requests
	DiscoveryPeriod = 5 * time.Minute  // time between peer discovery runs
)

//----------------------------------------------------------------------
// "GNUnet R5N DHT" service implementation
//----------------------------------------------------------------------

// Service implements a DHT service
type Service struct {
	Module
}

// NewService creates a new DHT service instance
func NewService(ctx context.Context, c *core.Core, cfg *config.DHTConfig) (*Service, error) {
	mod, err := NewModule(ctx, c, cfg)
	if err != nil {
		return nil, err
	}
	srv := &Service{
		Module: *mod,
	}
	return srv, nil
}

// ServeClient processes a client channel.
func (s *Service) ServeClient(ctx context.Context, id int, mc *service.Connection) {
	reqID := 0
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)

loop:
	for {
		// receive next message from client
		reqID++
		logger.Printf(logger.DBG, "[dht:%d:%d] Waiting for client request...\n", id, reqID)
		msg, err := mc.Receive(ctx)
		if err != nil {
			if err == io.EOF {
				logger.Printf(logger.INFO, "[dht:%d:%d] Client channel closed.\n", id, reqID)
			} else if err == service.ErrConnectionInterrupted {
				logger.Printf(logger.INFO, "[dht:%d:%d] Service operation interrupted.\n", id, reqID)
			} else {
				logger.Printf(logger.ERROR, "[dht:%d:%d] Message-receive failed: %s\n", id, reqID, err.Error())
			}
			break loop
		}
		logger.Printf(logger.INFO, "[dht:%d:%d] Received request: %v\n", id, reqID, msg)

		// handle message
		valueCtx := context.WithValue(ctx, core.CtxKey("label"), fmt.Sprintf(":%d:%d", id, reqID))
		s.HandleMessage(valueCtx, nil, msg, mc)
	}
	// close client connection
	mc.Close()

	// cancel all tasks running for this session/connection
	logger.Printf(logger.INFO, "[dht:%d] Start closing session...\n", id)
	cancel()
}
