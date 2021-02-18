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
	"sync"

	"gnunet/util"

	"github.com/bfix/gospel/concurrent"
)

// SessionContext is used to set a context for each client connection handled
// by a service; the session is handled by the 'ServeClient' method of a
// service implementation.
type SessionContext struct {
	ID       int                   // session identifier
	wg       *sync.WaitGroup       // wait group for the session
	sig      *concurrent.Signaller // signaller for the session
	pending  int                   // number of pending go-routines
	active   bool                  // is the context active (un-cancelled)?
	onCancel *sync.Mutex           // only run one Cancel() at a time
}

// NewSessionContext instantiates a new session context.
func NewSessionContext() *SessionContext {
	return &SessionContext{
		ID:       util.NextID(),
		wg:       new(sync.WaitGroup),
		sig:      concurrent.NewSignaller(),
		pending:  0,
		active:   true,
		onCancel: new(sync.Mutex),
	}
}

// Cancel all go-routines associated with this context.
func (ctx *SessionContext) Cancel() {
	ctx.onCancel.Lock()
	if ctx.active {
		// we are going out-of-business
		ctx.active = false
		// send signal to terminate...
		ctx.sig.Send(true)
		// wait for session go-routines to finish
		ctx.wg.Wait()
	}
	ctx.onCancel.Unlock()
}

// Add a go-routine to the wait group.
func (ctx *SessionContext) Add() {
	ctx.wg.Add(1)
	ctx.pending++
}

// Remove a go-routine from the wait group.
func (ctx *SessionContext) Remove() {
	ctx.wg.Done()
	ctx.pending--
}

// Waiting returns the number of waiting go-routines.
func (ctx *SessionContext) Waiting() int {
	return ctx.pending
}

// Signaller returns the working instance for the context.
func (ctx *SessionContext) Signaller() *concurrent.Signaller {
	return ctx.sig
}
