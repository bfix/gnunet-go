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
	"errors"
	"gnunet/config"
	"gnunet/crypto"
	"gnunet/message"
	"gnunet/transport"
	"gnunet/util"
	"net"
	"strings"
	"time"

	"github.com/bfix/gospel/logger"
)

// ----------------------------------------------------------------------
// Core-related error codes
var (
	ErrCoreNoUpnpDyn  = errors.New("no dynamic port with UPnP")
	ErrCoreNoEndpAddr = errors.New("no endpoint for address")
	ErrCoreNotSent    = errors.New("message not sent")
)

// CtxKey is a value-context key
type CtxKey string

// ----------------------------------------------------------------------
// EndpointRef is a reference to an endpoint instance managed by core.
type EndpointRef struct {
	id     string             // endpoint identifier in configuration
	ep     transport.Endpoint // reference to endpoint
	addr   *util.Address      // public endpoint address
	upnpID string             // UPNP identifier (empty if unused)
}

// ----------------------------------------------------------------------
// Core service
type Core struct {
	// local peer instance
	local *Peer

	// incoming messages from transport
	incoming chan *transport.Message

	// reference to transport implementation
	trans *transport.Transport

	// registered signal listeners
	listeners map[string]*Listener

	// list of known peers with addresses
	peers *util.PeerAddrList

	// list of connected peers
	connected *util.Map[string, bool]

	// List of registered endpoints
	endpoints map[string]*EndpointRef
}

//----------------------------------------------------------------------

// NewCore creates and runs a new core instance.
func NewCore(ctx context.Context, node *config.NodeConfig) (c *Core, err error) {
	// instantiate peer
	var peer *Peer
	if peer, err = NewLocalPeer(node); err != nil {
		return
	}
	logger.Printf(logger.INFO, "[core] Local node is %s", peer.GetID().Short())

	// create new core instance
	incoming := make(chan *transport.Message)
	c = &Core{
		local:     peer,
		incoming:  incoming,
		listeners: make(map[string]*Listener),
		trans:     transport.NewTransport(ctx, node.Name, incoming),
		peers:     util.NewPeerAddrList(),
		connected: util.NewMap[string, bool](),
		endpoints: make(map[string]*EndpointRef),
	}
	// add all local peer endpoints to transport.
	for _, epCfg := range node.Endpoints {
		var (
			upnpID string             // upnp identifier
			local  *util.Address      // local address
			remote *util.Address      // remote address
			ep     transport.Endpoint // endpoint reference
		)
		// handle special addresses:
		if strings.HasPrefix(epCfg.Address, "upnp:") {
			// don't allow dynamic port assignment
			if epCfg.Port == 0 {
				err = ErrCoreNoUpnpDyn
				return
			}
			// handle UPNP port forwarding
			protocol := transport.EpProtocol(epCfg.Network)
			var localA, remoteA string
			if upnpID, remoteA, localA, err = c.trans.ForwardOpen(protocol, epCfg.Address[5:], epCfg.Port); err != nil {
				return
			}
			// parse local and remote addresses
			if local, err = util.ParseAddress(epCfg.Network + "://" + localA); err != nil {
				return
			}
			if remote, err = util.ParseAddress(epCfg.Network + "://" + remoteA); err != nil {
				return
			}
		} else {
			// direct address specification:
			if local, err = util.ParseAddress(epCfg.Addr()); err != nil {
				return
			}
			remote = local
			upnpID = ""
		}
		// add endpoint for address
		if ep, err = c.trans.AddEndpoint(ctx, local); err != nil {
			return
		}
		// if port is set to 0, replace it with port assigned dynamically.
		// only applies to direct listening addresses!
		if epCfg.Port == 0 && local == remote {
			addr := ep.Address()
			if remote, err = util.ParseAddress(addr.Network() + "://" + addr.String()); err != nil {
				return
			}
		}
		// save endpoint reference
		c.endpoints[epCfg.ID] = &EndpointRef{
			id:     epCfg.ID,
			ep:     ep,
			addr:   remote,
			upnpID: upnpID,
		}
	}
	// run message pump
	go c.pump(ctx)
	return
}

// message pump for core
func (c *Core) pump(ctx context.Context) {
	// wait for incoming messages
	for {
		select {
		// get (next) message from transport
		case tm := <-c.incoming:
			logger.Printf(logger.DBG, "[core] Message received from %s: %s", tm.Peer.Short(), tm.Msg)

			// check if peer is already connected (has an entry in PeerAddrist)
			_, connected := c.connected.Get(tm.Peer.String(), 0)
			if !connected {
				// no: mark connected
				c.connected.Put(tm.Peer.String(), true, 0)
				// generate EV_CONNECT event
				c.dispatch(&Event{
					ID:   EV_CONNECT,
					Peer: tm.Peer,
				})
				// grace period for connection signal
				time.Sleep(time.Second)
			}

			// set default responder (core) if no custom responder
			// is defined by the receiving endpoint.
			resp := tm.Resp
			if resp == nil {
				resp = &transport.TransportResponder{
					Peer:    tm.Peer,
					SendFcn: c.Send,
				}
			}
			// generate EV_MESSAGE event
			c.dispatch(&Event{
				ID:   EV_MESSAGE,
				Peer: tm.Peer,
				Msg:  tm.Msg,
				Resp: resp,
			})

		// wait for termination
		case <-ctx.Done():
			return
		}
	}
}

// Shutdown all core-related processes.
func (c *Core) Shutdown() {
	c.trans.Shutdown()
	c.local.Shutdown()
}

//----------------------------------------------------------------------

// Send is a function that allows the local peer to send a protocol
// message to a remote peer.
func (c *Core) Send(ctx context.Context, peer *util.PeerID, msg message.Message) (err error) {
	// assemble log label
	label := "core"
	if v := ctx.Value(CtxKey("label")); v != nil {
		if s, ok := v.(string); ok && len(s) > 0 {
			label = s
		}
	}

	// TODO: select best endpoint protocol for transport; now fixed to IP+UDP
	netw := "ip+udp"

	// try all addresses for peer
	aList := c.peers.Get(peer, netw)
	maybe := false // message may be sent...
	for _, addr := range aList {
		logger.Printf(logger.INFO, "[%s] Trying to send to %s", label, addr.URI())
		// send message to address
		if err = c.SendToAddr(ctx, addr, msg); err != nil {
			// if it is possible that the message was not sent, try next address
			if err != transport.ErrEndpMaybeSent {
				logger.Printf(logger.WARN, "[%s] Failed to send to %s: %s", label, addr.URI(), err.Error())
			} else {
				maybe = true
			}
			continue
		}
		// one successful send is enough
		return
	}
	if maybe {
		err = nil
	} else {
		err = ErrCoreNotSent
	}
	return
}

// SendToAddr message directly to address
func (c *Core) SendToAddr(ctx context.Context, addr *util.Address, msg message.Message) error {
	// assemble transport message
	tm := transport.NewTransportMessage(c.PeerID(), msg)
	// send on transport
	return c.trans.Send(ctx, addr, tm)
}

// Learn (new) addresses for peer
func (c *Core) Learn(ctx context.Context, peer *util.PeerID, addrs []*util.Address, label string) (newPeer bool) {
	logger.Printf(logger.DBG, "[%s] Learning %v for %s", label, addrs, peer.Short())

	// learn all addresses for peer
	newPeer = false
	for _, addr := range addrs {
		// filter out addresses we can't handle (including local addresses)
		if !transport.CanHandleAddress(addr) {
			continue
		}
		// learn address
		logger.Printf(logger.INFO, "[%s] Learning %s for %s (expires %s)",
			label, addr.URI(), peer.Short(), addr.Expire)
		newPeer = (c.peers.Add(peer, addr) == 1) || newPeer
	}
	return
}

// Addresses returns the list of listening endpoint addresses
func (c *Core) Addresses() (list []*util.Address, err error) {
	for _, epRef := range c.endpoints {
		list = append(list, epRef.addr)
	}
	return
}

//----------------------------------------------------------------------

// Peer returns the local peer
func (c *Core) Peer() *Peer {
	return c.local
}

// PeerID returns the peer id of the local node.
func (c *Core) PeerID() *util.PeerID {
	return c.local.GetID()
}

//----------------------------------------------------------------------

// Sign a signable onject with private peer key
func (c *Core) Sign(obj crypto.Signable) error {
	sd := obj.SignedData()
	sig, err := c.local.prv.EdSign(sd)
	if err != nil {
		return err
	}
	return obj.SetSignature(util.NewPeerSignature(sig.Bytes()))
}

//----------------------------------------------------------------------

// TryConnect is a function which allows the local peer to attempt the
// establishment of a connection to another peer using an address.
// When the connection attempt is successful, information on the new
// peer is offered through the PEER_CONNECTED signal.
func (c *Core) TryConnect(peer *util.PeerID, addr net.Addr) error {
	// TODO:
	return nil
}

// Hold is a function which tells the underlay to keep a hold on to a
// connection to a peer P. Underlays are usually limited in the number
// of active connections. With this function the DHT can indicate to the
// underlay which connections should preferably be preserved.
func (c *Core) Hold(peer *util.PeerID) {
	// TODO:
}

// Drop is a function which tells the underlay to drop the connection to a
// peer P. This function is only there for symmetry and used during the
// peer's shutdown to release all of the remaining HOLDs. As R5N always
// prefers the longest-lived connections, it would never drop an active
// connection that it has called HOLD() on before. Nevertheless, underlay
// implementations should not rely on this always being true. A call to
// DROP() also does not imply that the underlay must close the connection:
// it merely removes the preference to preserve the connection that was
// established by HOLD().
func (c *Core) Drop(peer *util.PeerID) {
	// TODO:
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
			if ev.ID == EV_MESSAGE {
				mt := ev.Msg.Type()
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
