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

package revocation

import (
	"io"

	"gnunet/message"
	"gnunet/service"
	"gnunet/transport"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// "GNUnet Revocation" service implementation
//----------------------------------------------------------------------

// RevocationService
type RevocationService struct {
	RevocationModule
}

// NewRevocationService
func NewRevocationService() service.Service {
	// instantiate service and assemble a new Revocation handler.
	inst := new(RevocationService)
	return inst
}

// Start the Revocation service
func (s *RevocationService) Start(spec string) error {
	return nil
}

// Stop the Revocation service
func (s *RevocationService) Stop() error {
	return nil
}

// Serve a client channel.
func (s *RevocationService) ServeClient(ctx *service.SessionContext, mc *transport.MsgChannel) {

	reqId := 0
loop:
	for {
		// receive next message from client
		reqId++
		logger.Printf(logger.DBG, "[revocation:%d:%d] Waiting for client request...\n", ctx.Id, reqId)
		msg, err := mc.Receive(ctx.Signaller())
		if err != nil {
			if err == io.EOF {
				logger.Printf(logger.INFO, "[revocation:%d:%d] Client channel closed.\n", ctx.Id, reqId)
			} else if err == transport.ErrChannelInterrupted {
				logger.Printf(logger.INFO, "[revocation:%d:%d] Service operation interrupted.\n", ctx.Id, reqId)
			} else {
				logger.Printf(logger.ERROR, "[revocation:%d:%d] Message-receive failed: %s\n", ctx.Id, reqId, err.Error())
			}
			break loop
		}
		logger.Printf(logger.INFO, "[revocation:%d:%d] Received request: %v\n", ctx.Id, reqId, msg)

		// handle request
		switch m := msg.(type) {
		case *message.RevocationQueryMsg:
			//----------------------------------------------------------
			// REVOCATION_QUERY
			//----------------------------------------------------------
			go func(id int, m *message.RevocationQueryMsg) {
				logger.Printf(logger.INFO, "[revocation:%d:%d] Query request received.\n", ctx.Id, id)
				var resp *message.RevocationQueryResponseMsg
				ctx.Add()
				defer func() {
					// send response
					if resp != nil {
						if err := mc.Send(resp, ctx.Signaller()); err != nil {
							logger.Printf(logger.ERROR, "[revocation:%d:%d] Failed to send response: %s\n", ctx.Id, id, err.Error())
						}
					}
					// go-routine finished
					logger.Printf(logger.DBG, "[revocation:%d:%d] Query request finished.\n", ctx.Id, id)
					ctx.Remove()
				}()

				pkey := ed25519.NewPublicKeyFromBytes(m.Zone)
				valid, err := s.RevocationQuery(ctx, pkey)
				if err != nil {
					logger.Printf(logger.ERROR, "[revocation:%d:%d] Failed to query revocation status: %s\n", ctx.Id, id, err.Error())
					if err == transport.ErrChannelInterrupted {
						resp = nil
					}
					return
				}
				resp = message.NewRevocationQueryResponseMsg(valid)
			}(reqId, m)

		case *message.RevocationRevokeMsg:
			//----------------------------------------------------------
			// REVOCATION_REVOKE
			//----------------------------------------------------------
			go func(id int, m *message.RevocationRevokeMsg) {
				logger.Printf(logger.INFO, "[revocation:%d:%d] Revoke request received.\n", ctx.Id, id)
				var resp *message.RevocationRevokeResponseMsg
				ctx.Add()
				defer func() {
					// send response
					if resp != nil {
						if err := mc.Send(resp, ctx.Signaller()); err != nil {
							logger.Printf(logger.ERROR, "[revocation:%d:%d] Failed to send response: %s\n", ctx.Id, id, err.Error())
						}
					}
					// go-routine finished
					logger.Printf(logger.DBG, "[revocation:%d:%d] Revoke request finished.\n", ctx.Id, id)
					ctx.Remove()
				}()

				pkey := ed25519.NewPublicKeyFromBytes(m.ZoneKey)
				valid, err := s.RevocationRevoke(ctx, m.PoW, pkey)
				if err != nil {
					logger.Printf(logger.ERROR, "[revocation:%d:%d] Failed to revoke key: %s\n", ctx.Id, id, err.Error())
					if err == transport.ErrChannelInterrupted {
						resp = nil
					}
					return
				}
				resp = message.NewRevocationRevokeResponseMsg(valid)
			}(reqId, m)

		default:
			//----------------------------------------------------------
			// UNKNOWN message type received
			//----------------------------------------------------------
			logger.Printf(logger.ERROR, "[revocation:%d:%d] Unhandled message of type (%d)\n", ctx.Id, reqId, msg.Header().MsgType)
			break loop
		}
	}
	// close client connection
	mc.Close()

	// cancel all tasks running for this session/connection
	logger.Printf(logger.INFO, "[revocation:%d] Start closing session... [%d]\n", ctx.Id, ctx.Waiting())
	ctx.Cancel()
}
