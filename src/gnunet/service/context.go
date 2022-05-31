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
	"context"
	"sync"

	"gnunet/util"
)

// SessionContext is used to set a context for each client connection handled
// by a service; the session is handled by the 'ServeClient' method of a
// service implementation.
type SessionContext struct {
	ID       int                // session identifier
	wg       *sync.WaitGroup    // wait group for the session
	ctx      context.Context    // execution context
	pending  int                // number of pending go-routines
	active   bool               // is the context active (un-cancelled)?
	onCancel sync.Mutex         // only run one Cancel() at a time
	cancel   context.CancelFunc // cancel context
}

// NewSessionContext instantiates a new session context.
func NewSessionContext(ctx context.Context) *SessionContext {
	c, cancel := context.WithCancel(ctx)
	return &SessionContext{
		ID:      util.NextID(),
		wg:      new(sync.WaitGroup),
		ctx:     c,
		pending: 0,
		active:  true,
		cancel:  cancel,
	}
}

// Cancel all go-routines associated with this context.
func (sc *SessionContext) Cancel() {
	sc.onCancel.Lock()
	if sc.active {
		// we are going out-of-business
		sc.active = false
		// send signal to terminate...
		sc.cancel()
		// wait for session go-routines to finish
		sc.wg.Wait()
	}
	sc.onCancel.Unlock()
}

// Add a go-routine to the wait group.
func (sc *SessionContext) Add() {
	sc.wg.Add(1)
	sc.pending++
}

// Remove a go-routine from the wait group.
func (sc *SessionContext) Remove() {
	sc.wg.Done()
	sc.pending--
}

// Waiting returns the number of waiting go-routines.
func (sc *SessionContext) Waiting() int {
	return sc.pending
}

func (sc *SessionContext) Context() context.Context {
	return sc.ctx
}
