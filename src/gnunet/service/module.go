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
	"gnunet/core"
	"time"
)

// Module is an interface for GNUnet service modules (workers).
//
// Modules can call other GNUnet services; these services can be used by
// sending messages to the respective service socket (the default way) or by
// calling the module functions directly (if the other module is compiled
// along with the calling module into one binary). The latter method requires
// calls to m.Export() and m.Import() to link the modules together (see
// example):
//
//    // create module instances
//    gnsMod = gns.NewModule(ctx, core)
//    dhtMod = dht.NewModule(ctx, core)
//    ncMod = namecache.NewModule(ctx, core)
//    revMod = revocation.NewModule(ctx, core)
//
//    // export module functions
//    fcn := make(map[string]any)
//    gnsMod.Export(fcn)
//    dhtMod.Export(fcn)
//    ncMod.Export(fcn)
//    revMod.Export(fcn)
//
//    // import (link) module functions
//    gnsMod.Import(fcn)
//    dhtMod.Import(fcn)
//    ncMod.Import(fcn)
//    revMod.Import(fcn)
//
// Exported and imported module function are identified by name defined in the
// Export() function. Import() functions that access functions in other modules
// need to use the same name for linking.
type Module interface {
	// Export functions by name
	Export(map[string]any)

	// Import functions by name
	Import(map[string]any)

	// InitRPC registers RPC commands for the module
	InitRPC(*JRPCServer)

	// Filter returns the event filter for the module
	Filter() *core.EventFilter
}

// EventHandler is a function prototype for event handling
type EventHandler func(context.Context, *core.Event)

// Heartbeat is a function prototype for periodic tasks
type Heartbeat func(context.Context)

// ModuleImpl is an event-handling type used by Module implementations.
type ModuleImpl struct {
	// channel for core events.
	ch chan *core.Event
}

// NewModuleImplementation returns a new base module and starts
func NewModuleImpl() (m *ModuleImpl) {
	return &ModuleImpl{
		ch: make(chan *core.Event),
	}
}

// Run event handling loop
func (m *ModuleImpl) Run(
	ctx context.Context,
	hdlr EventHandler, filter *core.EventFilter,
	pulse time.Duration, heartbeat Heartbeat,
) (listener *core.Listener) {
	// listener for registration
	listener = core.NewListener(m.ch, filter)

	// if no heartbeat handler is defined, set pulse to near flatline.
	if heartbeat == nil {
		pulse = 365 * 24 * time.Hour // once a year
	}
	tick := time.NewTicker(pulse)
	// run event loop
	go func() {
		for {
			select {
			// Handle events
			case event := <-m.ch:
				hCtx := context.WithValue(ctx, "label", event.Label)
				hdlr(hCtx, event)

			// wait for terminate signal
			case <-ctx.Done():
				return

			// handle heartbeat
			case <-tick.C:
				// check for defined heartbeat handler
				if heartbeat != nil {
					heartbeat(ctx)
				}
			}
		}
	}()
	return
}
