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

package gns

import (
	"encoding/hex"
	"fmt"
	"io"

	"gnunet/config"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

// Error codes
var (
	ErrInvalidID           = fmt.Errorf("Invalid/unassociated ID")
	ErrBlockExpired        = fmt.Errorf("Block expired")
	ErrInvalidResponseType = fmt.Errorf("Invald response type")
)

//----------------------------------------------------------------------
// "GNUnet Name System" service implementation
//----------------------------------------------------------------------

// GNSService
type GNSService struct {
	GNSModule
}

// NewGNSService
func NewGNSService() service.Service {
	// instantiate service and assemble a new GNS handler.
	inst := new(GNSService)
	inst.LookupLocal = inst.LookupNamecache
	inst.StoreLocal = inst.StoreNamecache
	inst.LookupRemote = inst.LookupDHT
	return inst
}

// Start the GNS service
func (s *GNSService) Start(spec string) error {
	return nil
}

// Stop the GNS service
func (s *GNSService) Stop() error {
	return nil
}

// Serve a client channel.
func (s *GNSService) ServeClient(ctx *service.SessionContext, mc *transport.MsgChannel) {

loop:
	for {
		// receive next message from client
		logger.Printf(logger.DBG, "[gns] Waiting for message in session '%d'...\n", ctx.Id)
		msg, err := mc.Receive(ctx.Signaller())
		if err != nil {
			if err == io.EOF {
				logger.Println(logger.INFO, "[gns] Client channel closed.")
			} else if err == transport.ErrChannelInterrupted {
				logger.Println(logger.INFO, "[gns] Service operation interrupted.")
			} else {
				logger.Printf(logger.ERROR, "[gns] Message-receive failed: %s\n", err.Error())
			}
			break loop
		}
		logger.Printf(logger.INFO, "[gns] Received msg: %v\n", msg)

		// perform lookup
		var resp message.Message
		switch m := msg.(type) {
		case *message.GNSLookupMsg:
			//----------------------------------------------------------
			// GNS_LOOKUP
			//----------------------------------------------------------
			logger.Println(logger.INFO, "[gns] Lookup request received.")
			respX := message.NewGNSLookupResultMsg(m.Id)
			resp = respX

			// perform lookup on block (locally and remote)
			go func() {
				ctx.Add()
				defer func() {
					// send response
					if resp != nil {
						if err := mc.Send(resp, ctx.Signaller()); err != nil {
							logger.Printf(logger.ERROR, "[gns] Failed to send response: %s\n", err.Error())
						}
					}
					// go-routine finished
					ctx.Remove()
				}()

				pkey := ed25519.NewPublicKeyFromBytes(m.Zone)
				label := m.GetName()
				kind := NewRRTypeList(int(m.Type))
				recset, err := s.Resolve(ctx, label, pkey, kind, int(m.Options), 0)
				if err != nil {
					logger.Printf(logger.ERROR, "[gns] Failed to lookup block: %s\n", err.Error())
					if err == transport.ErrChannelInterrupted {
						resp = nil
					}
					return
				}
				// handle records
				if recset != nil {
					logger.Printf(logger.DBG, "[gns] Received record set with %d entries\n", recset.Count)

					// get records from block
					if recset.Count == 0 {
						logger.Println(logger.WARN, "[gns] No records in block")
						return
					}
					// process records
					for i, rec := range recset.Records {
						logger.Printf(logger.DBG, "[gns] Record #%d: %v\n", i, rec)

						// is this the record type we are looking for?
						if rec.Type == m.Type || int(m.Type) == enums.GNS_TYPE_ANY {
							// add it to the response message
							respX.AddRecord(rec)
						}
					}
				}
			}()

		default:
			//----------------------------------------------------------
			// UNKNOWN message type received
			//----------------------------------------------------------
			logger.Printf(logger.ERROR, "[gns] Unhandled message of type (%d)\n", msg.Header().MsgType)
			break loop
		}
	}
	// cancel all tasks running for this session/connection
	logger.Printf(logger.INFO, "[gns] Start closing session '%d'...\n", ctx.Id)
	ctx.Cancel()

	// close client connection
	mc.Close()
}

// LookupNamecache
func (s *GNSService) LookupNamecache(ctx *service.SessionContext, query *Query) (block *message.GNSBlock, err error) {
	logger.Printf(logger.DBG, "[gns] LookupNamecache(%s)...\n", hex.EncodeToString(query.Key.Bits))

	// assemble Namecache request
	req := message.NewNamecacheLookupMsg(query.Key)
	req.Id = uint32(util.NextID())
	block = nil

	// get response from Namecache service
	var resp message.Message
	if resp, err = service.ServiceRequestResponse(ctx, "gns", "Namecache", config.Cfg.Namecache.Endpoint, req); err != nil {
		return
	}

	// handle message depending on its type
	logger.Println(logger.DBG, "[gns] Handling response from Namecache service")
	switch m := resp.(type) {
	case *message.NamecacheLookupResultMsg:
		// check for matching IDs
		if m.Id != req.Id {
			logger.Println(logger.ERROR, "[gns] Got response for unknown ID")
			err = ErrInvalidID
			break
		}
		// check if block was found
		if len(m.EncData) == 0 || util.IsNull(m.EncData) {
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
		block = new(message.GNSBlock)
		block.Signature = m.Signature
		block.DerivedKey = m.DerivedKey
		sb := new(message.SignedBlockData)
		sb.Purpose = new(crypto.SignaturePurpose)
		sb.Purpose.Purpose = enums.SIG_GNS_RECORD_SIGN
		sb.Purpose.Size = uint32(16 + len(m.EncData))
		sb.Expire = m.Expire
		sb.EncData = m.EncData
		block.Block = sb

		// verify and decrypt block
		if err = block.Verify(query.Zone, query.Label); err != nil {
			break
		}
		if err = block.Decrypt(query.Zone, query.Label); err != nil {
			break
		}
	default:
		logger.Printf(logger.ERROR, "[gns] Got invalid response type (%d)\n", m.Header().MsgType)
		err = ErrInvalidResponseType
	}
	return
}

// StoreNamecache
func (s *GNSService) StoreNamecache(ctx *service.SessionContext, block *message.GNSBlock) (err error) {
	logger.Println(logger.DBG, "[gns] StoreNamecache()...")

	// assemble Namecache request
	req := message.NewNamecacheCacheMsg(block)
	req.Id = uint32(util.NextID())

	// get response from Namecache service
	var resp message.Message
	if resp, err = service.ServiceRequestResponse(ctx, "gns", "Namecache", config.Cfg.Namecache.Endpoint, req); err != nil {
		return
	}

	// handle message depending on its type
	logger.Println(logger.DBG, "[gns] Handling response from Namecache service")
	switch m := resp.(type) {
	case *message.NamecacheCacheResponseMsg:
		// check for matching IDs
		if m.Id != req.Id {
			logger.Println(logger.ERROR, "[gns] Got response for unknown ID")
			err = ErrInvalidID
			break
		}
		// check result
		if m.Result == 0 {
			return nil
		}
		return fmt.Errorf("Failed with rc=%d", m.Result)
	default:
		logger.Printf(logger.ERROR, "[gns] Got invalid response type (%d)\n", m.Header().MsgType)
		err = ErrInvalidResponseType
	}
	return
}

// LookupDHT
func (s *GNSService) LookupDHT(ctx *service.SessionContext, query *Query) (block *message.GNSBlock, err error) {
	logger.Printf(logger.DBG, "[gns] LookupDHT(%s)...\n", hex.EncodeToString(query.Key.Bits))
	block = nil

	// client-connect to the DHT service
	logger.Println(logger.DBG, "[gns] Connecting to DHT service...")
	cl, err := service.NewClient(config.Cfg.DHT.Endpoint)
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
	reqGet := message.NewDHTClientGetMsg(query.Key)
	reqGet.Id = uint64(util.NextID())
	reqGet.ReplLevel = uint32(enums.DHT_GNS_REPLICATION_LEVEL)
	reqGet.Type = uint32(enums.BLOCK_TYPE_GNS_NAMERECORD)
	reqGet.Options = uint32(enums.DHT_RO_DEMULTIPLEX_EVERYWHERE)

	if err = interact(reqGet, true); err != nil {
		// check for aborted remote lookup: we need to cancel the query
		if err == transport.ErrChannelInterrupted {
			logger.Println(logger.WARN, "[gns] remote Lookup aborted -- cleaning up.")

			// send DHT GET_STOP request and terminate
			reqStop := message.NewDHTClientGetStopMsg(query.Key)
			reqStop.Id = reqGet.Id
			if err = interact(reqStop, false); err != nil {
				logger.Printf(logger.ERROR, "[gns] remote Lookup abort failed: %s\n", err.Error())
			}
			return nil, transport.ErrChannelInterrupted
		}
	}

	// handle response message depending on its type
	logger.Println(logger.DBG, "[gns] Handling response from DHT service")
	switch m := resp.(type) {
	case *message.DHTClientResultMsg:
		// check for matching IDs
		if m.Id != reqGet.Id {
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
		if int(m.Type) != enums.BLOCK_TYPE_GNS_NAMERECORD {
			logger.Println(logger.ERROR, "[gns] DHT response has wrong type")
			break
		}

		// get GNSBlock from message
		block = message.NewGNSBlock()
		if err = data.Unmarshal(block, m.Data); err != nil {
			logger.Printf(logger.ERROR, "[gns] can't read GNS block: %s\n", err.Error())
			break
		}
		// verify and decrypt block
		if err = block.Verify(query.Zone, query.Label); err != nil {
			break
		}
		if err = block.Decrypt(query.Zone, query.Label); err != nil {
			break
		}

		// we got a result from DHT that was not in the namecache,
		// so store it there now.
		if err = s.StoreNamecache(ctx, block); err != nil {
			logger.Printf(logger.ERROR, "[gns] can't store block in Namecache: %s\n", err.Error())
		}
	}
	return
}
