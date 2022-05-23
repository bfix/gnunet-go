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
	"fmt"
	"io"

	"gnunet/message"
	"gnunet/service"
	"gnunet/transport"

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
func NewService() service.Service {
	// instantiate service and assemble a new GNS handler.
	inst := new(Service)
	return inst
}

// Start the GNS service
func (s *Service) Start(spec string) error {
	return nil
}

// Stop the GNS service
func (s *Service) Stop() error {
	return nil
}

// ServeClient processes a client channel.
func (s *Service) ServeClient(ctx *service.SessionContext, mc *transport.MsgChannel) {
	reqID := 0
loop:
	for {
		// receive next message from client
		reqID++
		logger.Printf(logger.DBG, "[dht:%d:%d] Waiting for client request...\n", ctx.ID, reqID)
		msg, err := mc.Receive(ctx.Signaller())
		if err != nil {
			if err == io.EOF {
				logger.Printf(logger.INFO, "[dht:%d:%d] Client channel closed.\n", ctx.ID, reqID)
			} else if err == transport.ErrChannelInterrupted {
				logger.Printf(logger.INFO, "[dht:%d:%d] Service operation interrupted.\n", ctx.ID, reqID)
			} else {
				logger.Printf(logger.ERROR, "[dht:%d:%d] Message-receive failed: %s\n", ctx.ID, reqID, err.Error())
			}
			break loop
		}
		logger.Printf(logger.INFO, "[dht:%d:%d] Received request: %v\n", ctx.ID, reqID, msg)

		// handle message
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
			logger.Printf(logger.ERROR, "[dht:%d:%d] Unhandled message of type (%d)\n", ctx.ID, reqID, msg.Header().MsgType)
			break loop
		}
	}
	// close client connection
	mc.Close()

	// cancel all tasks running for this session/connection
	logger.Printf(logger.INFO, "[dht:%d] Start closing session... [%d]\n", ctx.ID, ctx.Waiting())
	ctx.Cancel()
}
