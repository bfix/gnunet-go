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

package gns

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"gnunet/config"
	"gnunet/core"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service"
	"gnunet/service/dht/blocks"
	"gnunet/service/revocation"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

// Error codes
var (
	ErrInvalidID           = fmt.Errorf("invalid/unassociated ID")
	ErrBlockExpired        = fmt.Errorf("block expired")
	ErrInvalidResponseType = fmt.Errorf("invald response type")
)

//----------------------------------------------------------------------
// "GNUnet Name System" service implementation
//----------------------------------------------------------------------

// Service implements a GNS service
type Service struct {
	Module
}

// NewService creates a new GNS service instance
func NewService(ctx context.Context, c *core.Core) service.Service {
	// instantiate service
	mod := NewModule(ctx, c)
	srv := &Service{
		Module: *mod,
	}
	// set external function references (external services)
	srv.LookupLocal = srv.LookupNamecache
	srv.StoreLocal = srv.StoreNamecache
	srv.LookupRemote = srv.LookupDHT
	srv.RevocationQuery = srv.QueryKeyRevocation
	srv.RevocationRevoke = srv.RevokeKey

	return srv
}

// ServeClient processes a client channel.
func (s *Service) ServeClient(ctx context.Context, id int, mc *service.Connection) {
	reqID := 0
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)

	for {
		// receive next message from client
		reqID++
		logger.Printf(logger.DBG, "[gns:%d:%d] Waiting for client request...\n", id, reqID)
		msg, err := mc.Receive(ctx)
		if err != nil {
			if err == io.EOF {
				logger.Printf(logger.INFO, "[gns:%d:%d] Client channel closed.\n", id, reqID)
			} else if err == service.ErrConnectionInterrupted {
				logger.Printf(logger.INFO, "[gns:%d:%d] Service operation interrupted.\n", id, reqID)
			} else {
				logger.Printf(logger.ERROR, "[gns:%d:%d] Message-receive failed: %s\n", id, reqID, err.Error())
			}
			break
		}
		logger.Printf(logger.INFO, "[gns:%d:%d] Received request: %v\n", id, reqID, msg)

		// handle message
		valueCtx := context.WithValue(ctx, core.CtxKey("label"), fmt.Sprintf(":%d:%d", id, reqID))
		s.HandleMessage(valueCtx, nil, msg, mc)
	}
	// close client connection
	mc.Close()

	// cancel all tasks running for this session/connection
	logger.Printf(logger.INFO, "[gns:%d] Start closing session...\n", id)
	cancel()
}

// Handle a single incoming message
func (s *Service) HandleMessage(ctx context.Context, sender *util.PeerID, msg message.Message, back transport.Responder) bool {
	// assemble log label
	label := ""
	if v := ctx.Value("label"); v != nil {
		label, _ = v.(string)
	}
	// perform lookup
	switch m := msg.(type) {
	case *message.LookupMsg:
		//----------------------------------------------------------
		// GNS_LOOKUP
		//----------------------------------------------------------

		// perform lookup on block (locally and remote)
		go func(m *message.LookupMsg, label string) {
			logger.Printf(logger.INFO, "[gns%s] Lookup request received.\n", label)
			resp := message.NewGNSLookupResultMsg(m.ID)
			defer func() {
				// send response
				if resp != nil {
					if err := back.Send(ctx, resp); err != nil {
						logger.Printf(logger.ERROR, "[gns%s] Failed to send response: %s\n", label, err.Error())
					}
				}
				// go-routine finished
				logger.Printf(logger.DBG, "[gns%s] Lookup request finished.\n", label)
			}()

			kind := NewRRTypeList(m.RType)
			recset, err := s.Resolve(ctx, label, m.Zone, kind, int(m.Options), 0)
			if err != nil {
				logger.Printf(logger.ERROR, "[gns%s] Failed to lookup block: %s\n", label, err.Error())
				if err == service.ErrConnectionInterrupted {
					resp = nil
				}
				return
			}
			// handle records
			if recset != nil {
				logger.Printf(logger.DBG, "[gns%s] Received record set with %d entries\n", label, recset.Count)

				// get records from block
				if recset.Count == 0 {
					logger.Printf(logger.WARN, "[gns%s] No records in block\n", label)
					return
				}
				// process records
				for i, rec := range recset.Records {
					logger.Printf(logger.DBG, "[gns%s] Record #%d: %v\n", label, i, rec)

					// is this the record type we are looking for?
					if rec.RType == m.RType || m.RType == enums.GNS_TYPE_ANY {
						// add it to the response message
						if err := resp.AddRecord(rec); err != nil {
							logger.Printf(logger.ERROR, "[gns%s] failed: %sv", label, err.Error())
						}
					}
				}
			}
		}(m, label)

	default:
		//----------------------------------------------------------
		// UNKNOWN message type received
		//----------------------------------------------------------
		logger.Printf(logger.ERROR, "[gns%s] Unhandled message of type (%s)\n", label, msg.Type())
		return false
	}
	return true
}

//======================================================================
// Revocation-related methods
//======================================================================

// QueryKeyRevocation checks if a key has been revoked
func (s *Service) QueryKeyRevocation(ctx context.Context, zkey *crypto.ZoneKey) (valid bool, err error) {
	logger.Printf(logger.DBG, "[gns] QueryKeyRev(%s)...\n", util.EncodeBinaryToString(zkey.Bytes()))

	// assemble request
	req := message.NewRevocationQueryMsg(zkey)

	// get response from Revocation service
	var resp message.Message
	if resp, err = service.RequestResponse(ctx, "gns", "Revocation", config.Cfg.Revocation.Service.Socket, req, true); err != nil {
		return
	}

	// handle message depending on its type
	logger.Println(logger.DBG, "[gns] Handling response from Revocation service")
	valid = false
	switch m := resp.(type) {
	case *message.RevocationQueryResponseMsg:
		valid = (m.Valid == 1)
	}
	return
}

// RevokeKey revokes a key with given revocation data
func (s *Service) RevokeKey(ctx context.Context, rd *revocation.RevData) (success bool, err error) {
	logger.Printf(logger.DBG, "[gns] RevokeKey(%s)...\n", rd.ZoneKeySig.ID())

	// assemble request
	req := message.NewRevocationRevokeMsg(nil)
	req.Timestamp = rd.Timestamp
	copy(req.PoWs, rd.PoWs)
	req.ZoneKeySig = rd.ZoneKeySig

	// get response from Revocation service
	var resp message.Message
	if resp, err = service.RequestResponse(ctx, "gns", "Revocation", config.Cfg.Revocation.Service.Socket, req, true); err != nil {
		return
	}

	// handle message depending on its type
	logger.Println(logger.DBG, "[gns] Handling response from Revocation service")
	success = false
	switch m := resp.(type) {
	case *message.RevocationRevokeResponseMsg:
		success = (m.Success == 1)
	}
	return
}

//======================================================================
// Namecache-related methods
//======================================================================

// LookupNamecache returns a cached lookup (if available)
func (s *Service) LookupNamecache(ctx context.Context, query *blocks.GNSQuery) (block *blocks.GNSBlock, err error) {
	logger.Printf(logger.DBG, "[gns] LookupNamecache(%s)...\n", hex.EncodeToString(query.Key().Data))

	// assemble Namecache request
	req := message.NewNamecacheLookupMsg(query.Key())
	req.ID = uint32(util.NextID())
	block = nil

	// get response from Namecache service
	var resp message.Message
	if resp, err = service.RequestResponse(ctx, "gns", "Namecache", config.Cfg.Namecache.Service.Socket, req, true); err != nil {
		return
	}

	// handle message depending on its type
	logger.Println(logger.DBG, "[gns] Handling response from Namecache service")
	switch m := resp.(type) {
	case *message.NamecacheLookupResultMsg:
		// check for matching IDs
		if m.ID != req.ID {
			logger.Println(logger.ERROR, "[gns] Got response for unknown ID")
			err = ErrInvalidID
			break
		}
		// check if block was found
		if len(m.EncData) == 0 || util.IsAll(m.EncData, 0) {
			logger.Println(logger.DBG, "[gns] block not found in namecache")
			break
		}
		// check if record has expired
		if m.Expire.Expired() {
			logger.Printf(logger.ERROR, "[gns] block expired at %s\n", m.Expire)
			err = ErrBlockExpired
			break
		}

		// assemble GNSBlock from message
		block = new(blocks.GNSBlock)
		block.DerivedKeySig = m.DerivedKeySig
		sb := new(blocks.SignedGNSBlockData)
		sb.Purpose = new(crypto.SignaturePurpose)
		sb.Purpose.Purpose = enums.SIG_GNS_RECORD_SIGN
		sb.Purpose.Size = uint32(16 + len(m.EncData))
		sb.Expire = m.Expire
		sb.Data = m.EncData
		block.Body = sb

		// verify and decrypt block
		if err = query.Verify(block); err != nil {
			break
		}
		if err = query.Decrypt(block); err != nil {
			break
		}
	default:
		logger.Printf(logger.ERROR, "[gns] Got invalid response type (%s)\n", m.Type())
		err = ErrInvalidResponseType
	}
	return
}

// StoreNamecache stores a lookup in the local namecache.
func (s *Service) StoreNamecache(ctx context.Context, query *blocks.GNSQuery, block *blocks.GNSBlock) (err error) {
	logger.Println(logger.DBG, "[gns] StoreNamecache()...")

	// assemble Namecache request
	req := message.NewNamecacheCacheMsg(block)
	req.ID = uint32(util.NextID())

	// get response from Namecache service
	var resp message.Message
	if resp, err = service.RequestResponse(ctx, "gns", "Namecache", config.Cfg.Namecache.Service.Socket, req, true); err != nil {
		return
	}

	// handle message depending on its type
	logger.Println(logger.DBG, "[gns] Handling response from Namecache service")
	switch m := resp.(type) {
	case *message.NamecacheCacheResponseMsg:
		// check for matching IDs
		if m.ID != req.ID {
			logger.Println(logger.ERROR, "[gns] Got response for unknown ID")
			err = ErrInvalidID
			break
		}
		// check result
		if m.Result == 0 {
			return nil
		}
		return fmt.Errorf("failed with rc=%d", m.Result)
	default:
		logger.Printf(logger.ERROR, "[gns] Got invalid response type (%s)\n", m.Type())
		err = ErrInvalidResponseType
	}
	return
}

//======================================================================
// DHT-related methods
//======================================================================

// LookupDHT gets a GNS block from the DHT for the given query key.
func (s *Service) LookupDHT(ctx context.Context, query blocks.Query) (block blocks.Block, err error) {
	logger.Printf(logger.DBG, "[gns] LookupDHT(%s)...\n", hex.EncodeToString(query.Key().Data))
	block = nil

	// client-connect to the DHT service
	logger.Println(logger.DBG, "[gns] Connecting to DHT service...")
	cl, err := service.NewClient(ctx, config.Cfg.DHT.Service.Socket)
	if err != nil {
		return nil, err
	}
	defer func() {
		logger.Println(logger.DBG, "[gns] Closing connection to DHT service")
		cl.Close()
	}()

	var (
		// response received from service
		resp message.Message

		// request-response interaction with service
		interact = func(req message.Message, withResponse bool) (err error) {
			// send request
			logger.Println(logger.DBG, "[gns] Sending request to DHT service")
			if err = cl.SendRequest(ctx, req); err == nil && withResponse {
				// wait for a single response
				logger.Println(logger.DBG, "[gns] Waiting for response from DHT service")
				resp, err = cl.ReceiveResponse(ctx)
			}
			return
		}
	)

	// send DHT GET request and wait for response
	reqGet := message.NewDHTClientGetMsg(query.Key())
	reqGet.ID = uint64(util.NextID())
	reqGet.ReplLevel = uint32(enums.GNS_REPLICATION_LEVEL)
	reqGet.BType = enums.BLOCK_TYPE_GNS_NAMERECORD
	reqGet.Options = uint32(enums.DHT_RO_DEMULTIPLEX_EVERYWHERE)

	if err = interact(reqGet, true); err != nil {
		// check for aborted remote lookup: we need to cancel the query
		if err == service.ErrConnectionInterrupted {
			logger.Println(logger.WARN, "[gns] remote Lookup aborted -- cleaning up.")

			// send DHT GET_STOP request and terminate
			reqStop := message.NewDHTClientGetStopMsg(query.Key())
			reqStop.ID = reqGet.ID
			if err = interact(reqStop, false); err != nil {
				logger.Printf(logger.ERROR, "[gns] remote Lookup abort failed: %s\n", err.Error())
			}
			return nil, service.ErrConnectionInterrupted
		}
	}

	// handle response message depending on its type
	logger.Println(logger.DBG, "[gns] Handling response from DHT service")
	switch m := resp.(type) {
	case *message.DHTClientResultMsg:
		// check for matching IDs
		if m.ID != reqGet.ID {
			logger.Println(logger.ERROR, "[gns] Got response for unknown ID")
			break
		}
		// check if block was found
		if len(m.Data) == 0 {
			logger.Println(logger.DBG, "[gns] block not found in DHT")
			break
		}
		// check if record has expired
		if m.Expire.Expired() {
			logger.Printf(logger.ERROR, "[gns] block expired at %s\n", m.Expire)
			break
		}
		// check if result is of requested type
		if m.BType != enums.BLOCK_TYPE_GNS_NAMERECORD {
			logger.Println(logger.ERROR, "[gns] DHT response has wrong type")
			break
		}

		// get GNSBlock from message
		qGNS, _ := query.(*blocks.GNSQuery)
		block = new(blocks.GNSBlock)
		if err = data.Unmarshal(block, m.Data); err != nil {
			logger.Printf(logger.ERROR, "[gns] can't read GNS block: %s\n", err.Error())
			break
		}

		// verify and decrypt block
		if err = qGNS.Verify(block); err != nil {
			break
		}
		if err = qGNS.Decrypt(block); err != nil {
			break
		}

		// we got a result from DHT that was not in the namecache,
		// so store it there now.
		if err = s.StoreNamecache(ctx, qGNS, block.(*blocks.GNSBlock)); err != nil {
			logger.Printf(logger.ERROR, "[gns] can't store block in Namecache: %s\n", err.Error())
		}
	}
	return
}
