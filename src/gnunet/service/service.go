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

package service

import (
	"fmt"
	"sync"

	"gnunet/transport"

	"github.com/bfix/gospel/logger"
)

// Service is an interface for GNUnet services. Every service has one channel
// end-point it listens to for incoming channel requests (network-based
// channels established by service clients). The end-point is specified in
// Channel semantics in the specification string.
type Service interface {
	Start(spec string) error
	ServeClient(ctx *SessionContext, ch *transport.MsgChannel)
	Stop() error
}

// ServiceImpl is an implementation of generic service functionality.
type ServiceImpl struct {
	impl    Service                 // Specific service implementation
	hdlr    chan transport.Channel  // Channel from listener
	ctrl    chan bool               // Control channel
	drop    chan int                // Channel to drop a session from pending list
	srvc    transport.ChannelServer // multi-user service
	wg      *sync.WaitGroup         // wait group for go routine synchronization
	name    string                  // service name
	running bool                    // service currently running?
	pending map[int]*SessionContext // list of pending sessions
}

// NewServiceImpl instantiates a new ServiceImpl object.
func NewServiceImpl(name string, srv Service) *ServiceImpl {
	return &ServiceImpl{
		impl:    srv,
		hdlr:    make(chan transport.Channel),
		ctrl:    make(chan bool),
		drop:    make(chan int),
		srvc:    nil,
		wg:      new(sync.WaitGroup),
		name:    name,
		running: false,
		pending: make(map[int]*SessionContext),
	}
}

// Start a service
func (si *ServiceImpl) Start(spec string) (err error) {
	// check if we are already running
	if si.running {
		logger.Printf(logger.ERROR, "Service '%s' already running.\n", si.name)
		return fmt.Errorf("service already running")
	}

	// start channel server
	logger.Printf(logger.INFO, "[%s] Service starting.\n", si.name)
	if si.srvc, err = transport.NewChannelServer(spec, si.hdlr); err != nil {
		return
	}
	si.running = true

	// handle clients
	si.wg.Add(1)
	go func() {
		defer si.wg.Done()
	loop:
		for si.running {
			select {

			// handle incoming connections
			case in := <-si.hdlr:
				if in == nil {
					logger.Printf(logger.INFO, "[%s] Listener terminated.\n", si.name)
					break loop
				}
				switch ch := in.(type) {
				case transport.Channel:
					// run a new session with context
					ctx := NewSessionContext()
					sessId := ctx.Id
					si.pending[sessId] = ctx
					logger.Printf(logger.INFO, "[%s] Session '%d' started.\n", si.name, sessId)

					go func() {
						// serve client on the message channel
						si.impl.ServeClient(ctx, transport.NewMsgChannel(ch))
						// session is done now.
						logger.Printf(logger.INFO, "[%s] Session with client '%d' ended.\n", si.name, sessId)
						si.drop <- sessId
					}()
				}

			// handle session removal
			case sessId := <-si.drop:
				delete(si.pending, sessId)

			// handle cancelation signal on listener.
			case <-si.ctrl:
				break loop
			}
		}

		// terminate pending sessions
		for _, ctx := range si.pending {
			logger.Printf(logger.DBG, "[%s] Session '%d' closing...\n", si.name, ctx.Id)
			ctx.Cancel()
		}

		// close-down service
		logger.Printf(logger.INFO, "[%s] Service closing.\n", si.name)
		si.srvc.Close()
		si.running = false
	}()

	return si.impl.Start(spec)
}

// Stop a service
func (si *ServiceImpl) Stop() error {
	if !si.running {
		logger.Printf(logger.WARN, "Service '%s' not running.\n", si.name)
		return fmt.Errorf("service not running")
	}
	si.running = false
	si.ctrl <- true
	logger.Printf(logger.INFO, "[%s] Service terminating.\n", si.name)

	err := si.impl.Stop()
	si.wg.Wait()
	return err
}
