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
	"context"
	"gnunet/message"
	"gnunet/transport"
	"gnunet/util"
)

// Core service
type Core struct {
	// local peer instance
	local *Peer

	// incoming messages from transport
	incoming chan *transport.TransportMessage

	// reference to transport implementation
	trans *transport.Transport

	// registered listeners
	listeners map[string]*Listener
}

// NewCore creates a new core service.
func NewCore(ctx context.Context, local *Peer) (c *Core, err error) {
	// create new core instance
	c = new(Core)
	c.local = local
	c.incoming = make(chan *transport.TransportMessage)
	c.listeners = make(map[string]*Listener)
	c.trans = transport.NewTransport(ctx, c.incoming)

	// add all local peer endpoints to transport.
	for _, addr := range local.addrList {
		if _, err = c.trans.AddEndpoint(ctx, addr); err != nil {
			return
		}
	}

	// run message pump
	go func() {
		// wait for incoming messages
		for {
			select {
			// get (next) message from transport
			case tm := <-c.incoming:
				var ev *Event

				// inspect message for peer state events
				switch msg := tm.Msg.(type) {
				case *message.HelloMsg:
					// keep peer addresses
					for _, addr := range msg.Addresses {
						a := &util.Address{
							Netw:    addr.Transport,
							Address: addr.Address,
							Expires: addr.ExpireOn,
						}
						c.trans.Learn(msg.PeerID, a)
					}
					// generate EV_CONNECT event
					ev = new(Event)
					ev.ID = EV_CONNECT
					ev.Peer = msg.PeerID
					ev.Msg = msg
					c.dispatch(ev)
				}
				// generate EV_MESSAGE event
				ev = new(Event)
				ev.ID = EV_MESSAGE
				ev.Peer = tm.Peer
				ev.Msg = tm.Msg
				c.dispatch(ev)

			// wait for termination
			case <-ctx.Done():
				return
			}
		}
	}()
	return
}

// PeerID returns the peer id of the local node.
func (c *Core) PeerID() *util.PeerID {
	return c.local.GetID()
}

//----------------------------------------------------------------------
// Event listener and event dispatch.
//----------------------------------------------------------------------

// Register a named event listener.
func (c *Core) Register(name string, l *Listener) {
	c.listeners[name] = l
}

// Unregister named event listener.
func (c *Core) Unregister(name string) *Listener {
	if l, ok := c.listeners[name]; ok {
		delete(c.listeners, name)
		return l
	}
	return nil
}

// internal: dispatch event to listeners
func (c *Core) dispatch(ev *Event) {
	// dispatch event to listeners
	for _, l := range c.listeners {
		if l.filter.CheckEvent(ev.ID) {
			mt := ev.Msg.Header().MsgType
			if ev.ID == EV_MESSAGE {
				if mt != 0 && !l.filter.CheckMsgType(mt) {
					// skip event
					return
				}
			}
			go func() {
				l.ch <- ev
			}()
		}
	}
}

// Send is a function that allows the local peer to send a protocol
// message to a remote peer. The transport will
func (c *Core) Send(ctx context.Context, peer *util.PeerID, msg message.Message) {}
