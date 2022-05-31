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
	"gnunet/util"
	"sync"

	"github.com/bfix/gospel/logger"
)

// Responder is a back-channel for messages generated during
// message processing.
type Responder interface {
	// Handle outgoing message
	Send(ctx context.Context, msg message.Message) error
}

// Service is an interface for GNUnet services. Every service has one channel
// end-point it listens to for incoming channel requests (network-based
// channels established by service clients). The end-point is specified in
// Channel semantics in the specification string.
type Service interface {
	Module

	// Start a service
	Start(ctx context.Context, path string) error

	// Serve a client session
	ServeClient(ctx context.Context, id int, mc *Connection)

	// Handle a single incoming message. Returns true if message was processed.
	HandleMessage(ctx context.Context, msg message.Message, resp Responder) bool

	// Stop the service
	Stop() error
}

// ServiceImpl is an implementation of generic service functionality.
type ServiceImpl struct {
	impl    Service            // Specific service implementation
	hdlr    chan *Connection   // Channel from listener
	srvc    *ConnectionManager // multi-client service
	wg      *sync.WaitGroup    // wait group for go routine synchronization
	name    string             // service name
	running bool               // service currently running?
}

// NewServiceImpl instantiates a new ServiceImpl object.
func NewServiceImpl(name string, srv Service) *ServiceImpl {
	return &ServiceImpl{
		impl:    srv,
		hdlr:    make(chan *Connection),
		srvc:    nil,
		wg:      new(sync.WaitGroup),
		name:    name,
		running: false,
	}
}

// Start a service
func (si *ServiceImpl) Start(ctx context.Context, path string, params map[string]string) (err error) {
	// check if we are already running
	if si.running {
		logger.Printf(logger.ERROR, "Service '%s' already running.\n", si.name)
		return fmt.Errorf("service already running")
	}

	// start connection manager
	logger.Printf(logger.INFO, "[%s] Service starting.\n", si.name)
	if si.srvc, err = NewConnectionManager(ctx, path, params, si.hdlr); err != nil {
		return
	}
	si.running = true

	// handle clients
	go func() {
	loop:
		for si.running {
			select {

			// handle incoming connections
			case conn := <-si.hdlr:
				// run a new session with context
				id := util.NextID()
				logger.Printf(logger.INFO, "[%s] Session '%d' started.\n", si.name, id)

				go func() {
					// serve client on the message channel
					si.impl.ServeClient(ctx, id, conn)
					// session is done now.
					logger.Printf(logger.INFO, "[%s] Session with client '%d' ended.\n", si.name, id)
				}()

			// handle termination
			case <-ctx.Done():
				logger.Printf(logger.INFO, "[%s] Listener terminated.\n", si.name)
				break loop
			}
		}

		// close-down service
		logger.Printf(logger.INFO, "[%s] Service closing.\n", si.name)
		si.srvc.Close()
		si.running = false
	}()

	return si.impl.Start(ctx, path)
}

// Stop a service
func (si *ServiceImpl) Stop() error {
	if !si.running {
		logger.Printf(logger.WARN, "Service '%s' not running.\n", si.name)
		return fmt.Errorf("service not running")
	}
	si.running = false
	logger.Printf(logger.INFO, "[%s] Service terminating.\n", si.name)
	return si.impl.Stop()
}
