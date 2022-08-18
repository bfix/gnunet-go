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

package revocation

import (
	"context"
	"fmt"
	"io"

	"gnunet/core"
	"gnunet/message"
	"gnunet/service"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// "GNUnet Revocation" service implementation
//----------------------------------------------------------------------

// Service implements a revocation service
type Service struct {
	Module
}

// NewService creates a new revocation service instance
func NewService(ctx context.Context, c *core.Core) service.Service {
	// instantiate service
	mod := NewModule(ctx, c)
	srv := &Service{
		Module: *mod,
	}
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
		logger.Printf(logger.DBG, "[revocation:%d:%d] Waiting for client request...\n", id, reqID)
		msg, err := mc.Receive(ctx)
		if err != nil {
			if err == io.EOF {
				logger.Printf(logger.INFO, "[revocation:%d:%d] Client channel closed.\n", id, reqID)
			} else if err == service.ErrConnectionInterrupted {
				logger.Printf(logger.INFO, "[revocation:%d:%d] Service operation interrupted.\n", id, reqID)
			} else {
				logger.Printf(logger.ERROR, "[revocation:%d:%d] Message-receive failed: %s\n", id, reqID, err.Error())
			}
			break
		}
		logger.Printf(logger.INFO, "[revocation:%d:%d] Received request: %v\n", id, reqID, msg)

		// handle message
		valueCtx := context.WithValue(ctx, core.CtxKey("label"), fmt.Sprintf(":%d:%d", id, reqID))
		s.HandleMessage(valueCtx, nil, msg, mc)
	}
	// close client connection
	mc.Close()

	// cancel all tasks running for this session/connection
	logger.Printf(logger.INFO, "[revocation:%d] Start closing session...\n", id)
	cancel()
}

// Handle a single incoming message
func (s *Service) HandleMessage(ctx context.Context, sender *util.PeerID, msg message.Message, back transport.Responder) bool {
	// assemble log label
	label := ""
	if v := ctx.Value("label"); v != nil {
		label, _ = v.(string)
	}
	switch m := msg.(type) {
	case *message.RevocationQueryMsg:
		//----------------------------------------------------------
		// REVOCATION_QUERY
		//----------------------------------------------------------
		go func(m *message.RevocationQueryMsg) {
			logger.Printf(logger.INFO, "[revocation%s] Query request received.\n", label)
			var resp *message.RevocationQueryResponseMsg
			defer func() {
				// send response
				if resp != nil {
					if err := back.Send(ctx, resp); err != nil {
						logger.Printf(logger.ERROR, "[revocation%s] Failed to send response: %s\n", label, err.Error())
					}
				}
				// go-routine finished
				logger.Printf(logger.DBG, "[revocation%s] Query request finished.\n", label)
			}()

			valid, err := s.Query(ctx, m.Zone)
			if err != nil {
				logger.Printf(logger.ERROR, "[revocation%s] Failed to query revocation status: %s\n", label, err.Error())
				if err == service.ErrConnectionInterrupted {
					resp = nil
				}
				return
			}
			resp = message.NewRevocationQueryResponseMsg(valid)
		}(m)

	case *message.RevocationRevokeMsg:
		//----------------------------------------------------------
		// REVOCATION_REVOKE
		//----------------------------------------------------------
		go func(m *message.RevocationRevokeMsg) {
			logger.Printf(logger.INFO, "[revocation%s] Revoke request received.\n", label)
			var resp *message.RevocationRevokeResponseMsg
			defer func() {
				// send response
				if resp != nil {
					if err := back.Send(ctx, resp); err != nil {
						logger.Printf(logger.ERROR, "[revocation%s] Failed to send response: %s\n", label, err.Error())
					}
				}
				// go-routine finished
				logger.Printf(logger.DBG, "[revocation%s] Revoke request finished.\n", label)
			}()

			rd := NewRevDataFromMsg(m)
			valid, err := s.Revoke(ctx, rd)
			if err != nil {
				logger.Printf(logger.ERROR, "[revocation%s] Failed to revoke key: %s\n", label, err.Error())
				if err == service.ErrConnectionInterrupted {
					resp = nil
				}
				return
			}
			resp = message.NewRevocationRevokeResponseMsg(valid)
		}(m)

	default:
		//----------------------------------------------------------
		// UNKNOWN message type received
		//----------------------------------------------------------
		logger.Printf(logger.ERROR, "[revocation%s] Unhandled message of type (%s)\n", label, msg.Type())
		return false
	}
	return true
}
