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

package dht

import (
	"context"
	"fmt"
	"io"

	"gnunet/core"
	"gnunet/message"
	"gnunet/service"

	"github.com/bfix/gospel/logger"
)

// Error codes
var (
	ErrInvalidID           = fmt.Errorf("invalid/unassociated ID")
	ErrBlockExpired        = fmt.Errorf("block expired")
	ErrInvalidResponseType = fmt.Errorf("invald response type")
)

//----------------------------------------------------------------------
// "GNUnet R5N DHT" service implementation
//----------------------------------------------------------------------

// Service implements a DHT service
type Service struct {
	Module
}

// NewService creates a new DHT service instance
func NewService(ctx context.Context, c *core.Core) service.Service {
	return &Service{
		Module: *NewModule(ctx, c),
	}
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
		s.HandleMessage(context.WithValue(ctx, "label", fmt.Sprintf(":%d:%d", id, reqID)), msg, mc)
	}
	// close client connection
	mc.Close()

	// cancel all tasks running for this session/connection
	logger.Printf(logger.INFO, "[dht:%d] Start closing session...\n", id)
	cancel()
}

// HandleMessage handles a DHT request/response message. If the transport channel
// is nil, responses are send directly via the transport layer.
func (s *Service) HandleMessage(ctx context.Context, msg message.Message, back service.Responder) bool {
	// assemble log label
	label := ""
	if v := ctx.Value("label"); v != nil {
		label = v.(string)
	}
	// process message
	switch msg.(type) {
	case *message.DHTClientPutMsg:
		//----------------------------------------------------------
		// DHT PUT
		//----------------------------------------------------------

	case *message.DHTClientGetMsg:
		//----------------------------------------------------------
		// DHT GET
		//----------------------------------------------------------

	case *message.DHTClientGetResultsKnownMsg:
		//----------------------------------------------------------
		// DHT GET-RESULTS-KNOWN
		//----------------------------------------------------------

	case *message.DHTClientGetStopMsg:
		//----------------------------------------------------------
		// DHT GET-STOP
		//----------------------------------------------------------

	case *message.DHTClientResultMsg:
		//----------------------------------------------------------
		// DHT RESULT
		//----------------------------------------------------------

	default:
		//----------------------------------------------------------
		// UNKNOWN message type received
		//----------------------------------------------------------
		logger.Printf(logger.ERROR, "[dht%s] Unhandled message of type (%d)\n", label, msg.Header().MsgType)
		return false
	}
	return true
}
