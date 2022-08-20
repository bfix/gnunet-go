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

package dht

import (
	"context"
	"encoding/hex"
	"fmt"
	"gnunet/config"
	"gnunet/core"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service"
	"gnunet/service/dht/blocks"
	"gnunet/service/store"
	"gnunet/util"
	gmath "math"
	"time"

	"github.com/bfix/gospel/logger"
)

//======================================================================
// "DHT" implementation
//======================================================================

//----------------------------------------------------------------------
// Responder for local message handling (API, not message-based)
//----------------------------------------------------------------------

// LocalBlockResponder is a message handler used to handle results for
// locally initiated GET calls
type LocalBlockResponder struct {
	ch chan blocks.Block   // out-going channel for incoming block results
	rf blocks.ResultFilter // filter out duplicates
}

// NewLocalBlockResponder returns a new instance
func NewLocalBlockResponder() *LocalBlockResponder {
	return &LocalBlockResponder{
		ch: make(chan blocks.Block),
		rf: blocks.NewGenericResultFilter(),
	}
}

// C returns the back-channel
func (lr *LocalBlockResponder) C() <-chan blocks.Block {
	return lr.ch
}

// Send interface method: dissect message and relay block if appropriate
func (lr *LocalBlockResponder) Send(ctx context.Context, msg message.Message) error {
	// check if incoming message is a DHT-RESULT
	switch res := msg.(type) {
	case *message.DHTP2PResultMsg:
		// deliver incoming blocks
		go func() {
			blk, err := blocks.NewBlock(res.BType, res.Expire, res.Block)
			if err == nil {
				lr.ch <- blk
			} else {
				logger.Println(logger.WARN, "[local] DHT-RESULT block problem: "+err.Error())
			}
		}()
	default:
		logger.Printf(logger.WARN, "[local] %d not a DHT-RESULT -- skipped", msg.Type())
	}
	return nil
}

// Receiver is nil for local responders.
func (lr *LocalBlockResponder) Receiver() *util.PeerID {
	return nil
}

// Close back-channel
func (lr *LocalBlockResponder) Close() {
	close(lr.ch)
}

//----------------------------------------------------------------------
// Put and get blocks into/from a DHT.
//----------------------------------------------------------------------

// Module handles the permanent storage of blocks under a query key.
type Module struct {
	service.ModuleImpl

	cfg   *config.DHTConfig // configuraion parameters
	store *store.DHTStore   // reference to the block storage mechanism
	core  *core.Core        // reference to core services

	rtable    *RoutingTable           // routing table
	lastHello *message.DHTP2PHelloMsg // last own HELLO message used; re-create if expired
	reshdlrs  *ResultHandlerList      // list of open tasks
}

// NewModule returns a new module instance. It initializes the storage
// mechanism for persistence.
func NewModule(ctx context.Context, c *core.Core, cfg *config.DHTConfig) (m *Module, err error) {
	// create permanent storage handler
	var storage *store.DHTStore
	if storage, err = store.NewDHTStore(cfg.Storage); err != nil {
		return
	}
	// create routing table
	rt := NewRoutingTable(NewPeerAddress(c.PeerID()), cfg.Routing)

	// return module instance
	m = &Module{
		ModuleImpl: *service.NewModuleImpl(),
		cfg:        cfg,
		store:      storage,
		core:       c,
		rtable:     rt,
		reshdlrs:   NewResultHandlerList(),
	}
	// register as listener for core events
	pulse := time.Duration(cfg.Heartbeat) * time.Second
	listener := m.Run(ctx, m.event, m.Filter(), pulse, m.heartbeat)
	c.Register("dht", listener)

	// run periodic tasks (8.2. peer discovery)
	ticker := time.NewTicker(5 * time.Minute)
	key := crypto.Hash(m.core.PeerID().Bytes())
	flags := uint16(enums.DHT_RO_FIND_APPROXIMATE | enums.DHT_RO_DEMULTIPLEX_EVERYWHERE | enums.DHT_RO_DISCOVERY)
	var resCh <-chan blocks.Block
	go func() {
		for {
			select {
			// initiate peer discovery
			case <-ticker.C:
				// query DHT for our own HELLO block
				query := blocks.NewGenericQuery(key, enums.BLOCK_TYPE_DHT_URL_HELLO, flags)
				logger.Printf(logger.DBG, "[dht-discovery] own HELLO key %s", query.Key().Short())
				resCh = m.Get(ctx, query)

			// handle peer discover results
			case res := <-resCh:
				// check for correct type
				btype := res.Type()
				if btype == enums.BLOCK_TYPE_DHT_URL_HELLO {
					hb, ok := res.(*blocks.HelloBlock)
					if !ok {
						logger.Println(logger.WARN, "[dht-discovery] received invalid block data")
						logger.Printf(logger.DBG, "[dht-discovery] -> %s", hex.EncodeToString(res.Bytes()))
					} else {
						// cache HELLO block
						m.rtable.CacheHello(hb)
						// add sender to routing table
						m.rtable.Add(NewPeerAddress(hb.PeerID), "dht-discovery")
						// learn addresses
						m.core.Learn(ctx, hb.PeerID, hb.Addresses(), "dht-discovery")
					}
				} else {
					logger.Printf(logger.WARN, "[dht-discovery] received invalid block type %s", btype)
				}

			// termination
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
	return
}

//----------------------------------------------------------------------
// DHT methods for local use (API)
//----------------------------------------------------------------------

// Get blocks from the DHT ["dht:get"]
// Locally request blocks for a given query. The res channel will deliver the
// returned results to the caller; the channel is closed if no further blocks
// are expected or the query times out.
func (m *Module) Get(ctx context.Context, query blocks.Query) <-chan blocks.Block {
	// get the block handler for given block type to construct an empty
	// result filter. If no handler is defined, a default PassResultFilter
	// is created.
	var rf blocks.ResultFilter = new(blocks.GenericResultFilter)
	blockHdlr, ok := blocks.BlockHandlers[query.Type()]
	if ok {
		// create result filter
		rf = blockHdlr.SetupResultFilter(128, util.RndUInt32())
	} else {
		logger.Println(logger.WARN, "[dht] unknown result filter implementation -- skipped")
	}
	// get additional query parameters
	xquery, _ := util.GetParam[[]byte](query.Params(), "xquery")

	// assemble a new GET message
	msg := message.NewDHTP2PGetMsg()
	msg.BType = query.Type()
	msg.Flags = query.Flags()
	msg.HopCount = 0
	msg.Query = query.Key()
	msg.ReplLevel = uint16(m.cfg.Routing.ReplLevel)
	msg.PeerFilter = blocks.NewPeerFilter()
	msg.ResFilter = rf.Bytes()
	msg.RfSize = uint16(len(msg.ResFilter))
	msg.XQuery = xquery
	msg.MsgSize += msg.RfSize + uint16(len(xquery))

	// compose a response channel and handler
	hdlr := NewLocalBlockResponder()

	// time-out handling
	ttl, ok := util.GetParam[time.Duration](query.Params(), "timeout")
	if !ok {
		// defaults to 10 minutes
		ttl = 10 * time.Minute
	}
	lctx, cancel := context.WithTimeout(ctx, ttl)

	// send message
	self := m.core.PeerID()
	msg.PeerFilter.Add(self)
	go m.HandleMessage(lctx, self, msg, hdlr)
	go func() {
		<-lctx.Done()
		hdlr.Close()
		cancel()
	}()
	return hdlr.C()
}

// Put a block into the DHT ["dht:put"]
func (m *Module) Put(ctx context.Context, query blocks.Query, block blocks.Block) error {
	// get additional query parameters
	expire, ok := util.GetParam[util.AbsoluteTime](query.Params(), "expire")
	if !ok {
		expire = util.AbsoluteTimeNever()
	}
	// assemble a new PUT message
	msg := message.NewDHTP2PPutMsg()
	msg.BType = query.Type()
	msg.Flags = query.Flags()
	msg.HopCount = 0
	msg.PeerFilter = blocks.NewPeerFilter()
	msg.ReplLvl = uint16(m.cfg.Routing.ReplLevel)
	msg.Expire = expire
	msg.Block = block.Bytes()
	msg.Key = query.Key().Clone()
	msg.TruncOrigin = nil
	msg.PutPath = nil
	msg.LastSig = nil
	msg.MsgSize += uint16(len(msg.Block))

	// send message
	self := m.core.PeerID()
	msg.PeerFilter.Add(self)
	go m.HandleMessage(ctx, self, msg, nil)

	return nil
}

//----------------------------------------------------------------------
// Event handling
//----------------------------------------------------------------------

// Filter returns the event filter for the module
func (m *Module) Filter() *core.EventFilter {
	f := core.NewEventFilter()
	// events we are interested in
	f.AddEvent(core.EV_CONNECT)
	f.AddEvent(core.EV_DISCONNECT)

	// messages we are interested in:
	// (1) DHT_P2P messages
	f.AddMsgType(enums.MSG_DHT_P2P_PUT)
	f.AddMsgType(enums.MSG_DHT_P2P_GET)
	f.AddMsgType(enums.MSG_DHT_P2P_RESULT)
	f.AddMsgType(enums.MSG_DHT_P2P_HELLO)
	// (2) DHT messages (legacy, not implemented)
	f.AddMsgType(enums.MSG_DHT_CLIENT_GET)
	f.AddMsgType(enums.MSG_DHT_CLIENT_GET_RESULTS_KNOWN)
	f.AddMsgType(enums.MSG_DHT_CLIENT_GET_STOP)
	f.AddMsgType(enums.MSG_DHT_CLIENT_PUT)
	f.AddMsgType(enums.MSG_DHT_CLIENT_RESULT)

	return f
}

// Event handler for infrastructure signals
func (m *Module) event(ctx context.Context, ev *core.Event) {
	switch ev.ID {
	// New peer connected:
	case core.EV_CONNECT:
		// Add peer to routing table
		logger.Printf(logger.INFO, "[dht-event] Peer %s connected", ev.Peer.Short())
		m.rtable.Add(NewPeerAddress(ev.Peer), "dht-event")

	// Peer disconnected:
	case core.EV_DISCONNECT:
		// Remove peer from routing table
		logger.Printf(logger.INFO, "[dht-event] Peer %s disconnected", ev.Peer.Short())
		m.rtable.Remove(NewPeerAddress(ev.Peer), "dht-event", 0)

	// Message received.
	case core.EV_MESSAGE:
		// generate tracking label
		label := fmt.Sprintf("dht-msg-%d", util.NextID())
		tctx := context.WithValue(ctx, core.CtxKey("label"), label)
		// check if peer is in routing table (connected peer)
		if !m.rtable.Contains(NewPeerAddress(ev.Peer), label) {
			logger.Printf(logger.WARN, "[%s] message %d from unregistered peer -- discarded", label, ev.Msg.Type())
			return
		}
		// process message
		if !m.HandleMessage(tctx, ev.Peer, ev.Msg, ev.Resp) {
			logger.Printf(logger.WARN, "[%s] %s message NOT handled", label, ev.Msg.Type())
		}
	}
}

// ----------------------------------------------------------------------
// Heartbeat handler for periodic tasks
func (m *Module) heartbeat(ctx context.Context) {
	// run heartbeat for routing table
	m.rtable.heartbeat(ctx)

	// clean-up task list
	m.reshdlrs.Cleanup()
}

//----------------------------------------------------------------------
// HELLO handling
//----------------------------------------------------------------------

// Send the currently active HELLO to given network address
func (m *Module) SendHello(ctx context.Context, addr *util.Address, label string) (err error) {
	// get (buffered) HELLO
	var msg *message.DHTP2PHelloMsg
	if msg, err = m.getHello(label); err != nil {
		return
	}
	logger.Printf(logger.INFO, "[%s] Sending own HELLO to %s", label, addr.URI())
	return m.core.SendToAddr(ctx, addr, msg)
}

// get the recent HELLO if it is defined and not expired;
// create a new HELLO otherwise.
func (m *Module) getHello(label string) (msg *message.DHTP2PHelloMsg, err error) {
	if m.lastHello == nil || m.lastHello.Expire.Expired() {
		// assemble new (signed) HELLO block
		var addrList []*util.Address
		if addrList, err = m.core.Addresses(); err != nil {
			return
		}
		// assemble HELLO data
		hb := new(blocks.HelloBlock)
		hb.PeerID = m.core.PeerID()
		hb.SetExpire(message.HelloAddressExpiration)
		hb.SetAddresses(addrList)

		// sign HELLO block
		if err = m.core.Sign(hb); err != nil {
			return
		}
		// assemble HELLO message
		msg = message.NewDHTP2PHelloMsg()
		msg.Expire = hb.Expire_
		msg.SetAddresses(hb.Addresses())
		if err = m.core.Sign(msg); err != nil {
			return
		}
		// save for later use
		m.lastHello = msg

		// DEBUG
		var ok bool
		if ok, err = msg.Verify(m.core.PeerID()); !ok || err != nil {
			if !ok {
				err = fmt.Errorf("[%s] failed to verify own HELLO", label)
			}
			logger.Println(logger.ERROR, err.Error())
			return
		}
		logger.Printf(logger.INFO, "[%s] new own HELLO created (expires %s)", label, msg.Expire)
		return
	}
	// we have a valid HELLO for re-use.
	return m.lastHello, nil
}

//----------------------------------------------------------------------
// Inter-module linkage helpers
//----------------------------------------------------------------------

// Export functions
func (m *Module) Export(fcn map[string]any) {
	// add exported functions from module
	fcn["dht:get"] = m.Get
	fcn["dht:put"] = m.Put
}

// Import functions
func (m *Module) Import(fcn map[string]any) {
	// nothing to import for now.
}

//----------------------------------------------------------------------

// SetNetworkSize sets a fixed number of peers in the network
func (m *Module) SetNetworkSize(numPeers int) {
	m.rtable.l2nse = gmath.Log2(float64(numPeers))
}
