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
	"net/http"
)

// Module is an interface for GNUnet service modules (workers).
type Module interface {
	// RPC returns the route and handler for JSON-RPC requests
	RPC() (string, func(http.ResponseWriter, *http.Request))

	// Filter returns the event filter for the module
	Filter() *core.EventFilter
}

// EventHandler is a function prototype for event handling
type EventHandler func(context.Context, *core.Event)

// ModuleImpl is an event-handling type used by Module implementations.
type ModuleImpl struct {
	ch chan *core.Event // channel for core events.
}

// NewModuleImplementation returns a new base module and starts
func NewModuleImpl() (m *ModuleImpl) {
	return &ModuleImpl{
		ch: make(chan *core.Event),
	}
}

// Run event handling loop
func (m *ModuleImpl) Run(ctx context.Context, hdlr EventHandler, filter *core.EventFilter) (listener *core.Listener) {
	// listener for registration
	listener = core.NewListener(m.ch, filter)
	// run event loop
	go func() {
		for {
			select {
			// Handle events
			case event := <-m.ch:
				hdlr(ctx, event)

			// wait for terminate signal
			case <-ctx.Done():
				return
			}
		}
	}()
	return
}
