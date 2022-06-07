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

package core

import (
	"gnunet/message"
	"gnunet/transport"
	"gnunet/util"
)

//----------------------------------------------------------------------
// Core events and listeners
//----------------------------------------------------------------------

// Event types
const (
	EV_CONNECT    = iota // peer connected
	EV_DISCONNECT        // peer disconnected
	EV_MESSAGE           // incoming message
)

// EventFilter is a filter for events a listener is interested in.
// The filter works on event types; if EV_MESSAGE is set, messages
// can be filtered by message type also.
type EventFilter struct {
	evTypes  map[int]bool
	msgTypes map[uint16]bool
}

// NewEventFilter creates a new empty filter instance.
func NewEventFilter() *EventFilter {
	return &EventFilter{
		evTypes:  make(map[int]bool),
		msgTypes: make(map[uint16]bool),
	}
}

// AddEvent add  an event id to filter
func (f *EventFilter) AddEvent(ev int) {
	f.evTypes[ev] = true
}

// AddMsgType adds a message type to filter
func (f *EventFilter) AddMsgType(mt uint16) {
	f.evTypes[EV_MESSAGE] = true
	f.msgTypes[mt] = true
}

// CheckEvent returns true if an event id is matched
// by the filter or the filter is empty.
func (f *EventFilter) CheckEvent(ev int) bool {
	if len(f.evTypes) == 0 {
		return true
	}
	_, ok := f.evTypes[ev]
	return ok
}

// CheckMsgType returns true if a message type is matched
// by the filter or the filter is empty.
func (f *EventFilter) CheckMsgType(mt uint16) bool {
	if len(f.msgTypes) == 0 {
		return true
	}
	_, ok := f.msgTypes[mt]
	return ok
}

// Event sent to listeners
type Event struct {
	ID   int                 // event type
	Peer *util.PeerID        // remote peer
	Msg  message.Message     // GNUnet message (can be nil)
	Resp transport.Responder // reply handler (can be nil)
}

//----------------------------------------------------------------------

// Listener for network events
type Listener struct {
	ch     chan *Event  // listener channel
	filter *EventFilter // event filter settimgs
}

// NewListener for given filter and receiving channel
func NewListener(ch chan *Event, f *EventFilter) *Listener {
	if f == nil {
		// set empty default filter
		f = NewEventFilter()
	}
	return &Listener{
		ch:     ch,
		filter: f,
	}
}
