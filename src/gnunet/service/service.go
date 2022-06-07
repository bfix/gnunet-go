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

package service

import (
	"context"
	"fmt"
	"gnunet/message"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------

// Service is an interface for GNUnet services
type Service interface {
	Module

	// Serve a client session: A service has a socket it listens to for
	// incoming connections (sessions) which are used for message exchange
	// with local GNUnet services or clients.
	ServeClient(ctx context.Context, id int, mc *Connection)

	// Handle a single incoming message (either locally from a socket
	// connection or from Transport). Response messages can be send
	// via a Responder. Returns true if message was processed.
	HandleMessage(ctx context.Context, msg message.Message, resp transport.Responder) bool
}

// SocketHandler handles incoming connections on the local service socket.
// It delegates calls to ServeClient() and HandleMessage() methods
// to a custom service 'srv'.
type SocketHandler struct {
	srv  Service            // Specific service implementation
	hdlr chan *Connection   // handler for incoming connections
	cmgr *ConnectionManager // manager for client connections
	name string             // service name
}

// NewSocketHandler instantiates a new socket handler.
func NewSocketHandler(name string, srv Service) *SocketHandler {
	return &SocketHandler{
		srv:  srv,
		hdlr: make(chan *Connection),
		cmgr: nil,
		name: name,
	}
}

// Start the socket handler by listening on a Unix domain socket specified
// by its path and additional parameters. Incoming connections from clients
// are dispatched to 'hdlr'. Stopped socket handlers can be re-started.
func (h *SocketHandler) Start(ctx context.Context, path string, params map[string]string) (err error) {
	// check if we are already running
	if h.cmgr != nil {
		logger.Printf(logger.ERROR, "Service '%s' already running.\n", h.name)
		return fmt.Errorf("service already running")
	}
	// start connection manager
	logger.Printf(logger.INFO, "[%s] Service starting.\n", h.name)
	if h.cmgr, err = NewConnectionManager(ctx, path, params, h.hdlr); err != nil {
		return
	}

	// handle client connections
	go func() {
	loop:
		for {
			select {

			// handle incoming connection
			case conn := <-h.hdlr:
				// run a new session with context
				id := util.NextID()
				logger.Printf(logger.INFO, "[%s] Session '%d' started.\n", h.name, id)

				go func() {
					// serve client on the message channel
					h.srv.ServeClient(ctx, id, conn)
					// session is done now.
					logger.Printf(logger.INFO, "[%s] Session with client '%d' ended.\n", h.name, id)
				}()

			// handle termination
			case <-ctx.Done():
				logger.Printf(logger.INFO, "[%s] Listener terminated.\n", h.name)
				break loop
			}
		}

		// close-down service
		logger.Printf(logger.INFO, "[%s] Service closing.\n", h.name)
		h.cmgr.Close()
	}()
	return nil
}

// Stop socket handler.
func (h *SocketHandler) Stop() error {
	if h.cmgr == nil {
		logger.Printf(logger.WARN, "Service '%s' not running.\n", h.name)
		return fmt.Errorf("service not running")
	}
	logger.Printf(logger.INFO, "[%s] Service terminating.\n", h.name)
	h.cmgr.Close()
	h.cmgr = nil
	return nil
}
