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
	"gnunet/message"
	"gnunet/service/dht/blocks"
	"gnunet/transport"
	"gnunet/util"
	"net"
	"strings"
	"time"
)

//----------------------------------------------------------------------
// Core-related error codes
var (
	ErrCoreNoUpnpDyn  = errors.New("no dynamic port with UPnP")
	ErrCoreNoEndpAddr = errors.New("no endpoint for address")
)

//----------------------------------------------------------------------
// EndpointRef is a reference to an endpoint instance managed by core.
type EndpointRef struct {
	id     string             // endpoint identifier in configuration
	ep     transport.Endpoint // reference to endpoint
	addr   *util.Address      // public endpoint address
	upnpId string             // UPNP identifier (empty if unused)
}

//----------------------------------------------------------------------
// Core service
type Core struct {
	// local peer instance
	local *Peer

	// incoming messages from transport
	incoming chan *transport.TransportMessage

	// reference to transport implementation
	trans *transport.Transport

	// registered signal listeners
	listeners map[string]*Listener

	// list of known peers with addresses
	peers *util.PeerAddrList

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
	// create new core instance
	incoming := make(chan *transport.TransportMessage)
	c = &Core{
		local:     peer,
		incoming:  incoming,
		listeners: make(map[string]*Listener),
		trans:     transport.NewTransport(ctx, node.Name, incoming),
		peers:     util.NewPeerAddrList(),
		endpoints: make(map[string]*EndpointRef),
	}
	// add all local peer endpoints to transport.
	for _, epCfg := range node.Endpoints {
		var (
			upnpId string             // upnp identifier
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
			if upnpId, remoteA, localA, err = c.trans.ForwardOpen(protocol, epCfg.Address[5:], epCfg.Port); err != nil {
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
			upnpId = ""
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
			upnpId: upnpId,
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
						c.Learn(ctx, msg.PeerID, a)
					}
					// generate EV_CONNECT event
					ev = &Event{
						ID:   EV_CONNECT,
						Peer: tm.Peer,
						Msg:  msg,
					}
					c.dispatch(ev)
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
				ev = &Event{
					ID:   EV_MESSAGE,
					Peer: tm.Peer,
					Msg:  tm.Msg,
					Resp: tm.Resp,
				}
				c.dispatch(ev)

			// wait for termination
			case <-ctx.Done():
				return
			}
		}
	}()
	return
}

// Shutdown all core-related processes.
func (c *Core) Shutdown() {
	c.trans.Shutdown()
	c.local.Shutdown()
}

//----------------------------------------------------------------------

// Send is a function that allows the local peer to send a protocol
// message to a remote peer.
func (c *Core) Send(ctx context.Context, peer *util.PeerID, msg message.Message) error {
	// get peer label (id or "@")
	label := "@"
	if peer != nil {
		label = peer.String()
	}
	// TODO: select best endpoint protocol for transport; now fixed to IP+UDP
	netw := "ip+udp"
	addrs := c.peers.Get(label, netw)
	if len(addrs) == 0 {
		return ErrCoreNoEndpAddr
	}
	// TODO: select best address; curently selects first
	addr := addrs[0]
	return c.send(ctx, addr, msg)
}

// send message directly to address
func (c *Core) send(ctx context.Context, addr *util.Address, msg message.Message) error {
	// assemble transport message
	tm := transport.NewTransportMessage(c.PeerID(), msg)
	// send on transport
	return c.trans.Send(ctx, addr, tm)
}

// Learn a (new) address for peer
func (c *Core) Learn(ctx context.Context, peer *util.PeerID, addr *util.Address) (err error) {
	// assemble HELLO message:
	addrList := make([]*util.Address, 0)
	for _, epRef := range c.endpoints {
		addrList = append(addrList, epRef.addr)
	}
	node := c.local
	var hello *blocks.HelloBlock
	hello, err = node.HelloData(time.Hour, addrList)
	if err != nil {
		return
	}
	msg := message.NewHelloMsg(node.GetID())
	for _, a := range hello.Addresses() {
		ha := message.NewHelloAddress(a)
		msg.AddAddress(ha)
	}

	// if no peer is given, we send HELLO directly to address
	if peer == nil {
		return c.send(ctx, addr, msg)
	}
	// add peer address to address list
	if c.peers.Add(peer.String(), addr) == 1 {
		// we added a previously unknown peer: send a HELLO
		err = c.Send(ctx, peer, msg)
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

// TryConnect is a function which allows the local peer to attempt the
// establishment of a connection to another peer using an address.
// When the connection attempt is successful, information on the new
// peer is offered through the PEER_CONNECTED signal.
func (c *Core) TryConnect(peer *util.PeerID, addr net.Addr) error {
	// select endpoint for address
	if ep := c.findEndpoint(peer, addr); ep == nil {
		return transport.ErrTransNoEndpoint
	}
	return nil
}

func (c *Core) findEndpoint(peer *util.PeerID, addr net.Addr) transport.Endpoint {
	return nil
}

// Hold is a function which tells the underlay to keep a hold on to a
// connection to a peer P. Underlays are usually limited in the number
// of active connections. With this function the DHT can indicate to the
// underlay which connections should preferably be preserved.
func (c *Core) Hold(peer *util.PeerID) {}

// Drop is a function which tells the underlay to drop the connection to a
// peer P. This function is only there for symmetry and used during the
// peer's shutdown to release all of the remaining HOLDs. As R5N always
// prefers the longest-lived connections, it would never drop an active
// connection that it has called HOLD() on before. Nevertheless, underlay
// implementations should not rely on this always being true. A call to
// DROP() also does not imply that the underlay must close the connection:
// it merely removes the preference to preserve the connection that was
// established by HOLD().
func (c *Core) Drop(peer *util.PeerID) {}

// L2NSE is ESTIMATE_NETWORK_SIZE(), a procedure that provides estimates
// on the base-2 logarithm of the network size L2NSE, that is the base-2
// logarithm number of peers in the network, for use by the routing
// algorithm.
func (c *Core) L2NSE() float64 {
	return 0.
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
