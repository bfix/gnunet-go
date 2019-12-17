package gns

import (
	"encoding/hex"
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
	inst.GetLocalZone = inst.GetPrivateZone
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
func (s *GNSService) ServeClient(mc *transport.MsgChannel) {
	for {
		// receive next message from client
		msg, err := mc.Receive()
		if err != nil {
			if err == io.EOF {
				logger.Println(logger.INFO, "[gns] Client channel closed.")
			} else {
				logger.Printf(logger.ERROR, "[gns] Message-receive failed: %s\n", err.Error())
			}
			break
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
			// TODO: run code in a go routine concurrently (would need
			//       access to the message channel to send responses)
			pkey := ed25519.NewPublicKeyFromBytes(m.Zone)
			label := m.GetName()
			kind := NewRRTypeList(int(m.Type))
			recset, err := s.Resolve(label, pkey, kind, int(m.Options))
			if err != nil {
				logger.Printf(logger.ERROR, "[gns] Failed to lookup block: %s\n", err.Error())
				break
			}
			// handle records
			if recset != nil {
				logger.Printf(logger.DBG, "[gns] Received record set with %d entries\n", recset.Count)

				// get records from block
				if recset.Count == 0 {
					logger.Println(logger.WARN, "[gns] No records in block")
					break
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

		default:
			//----------------------------------------------------------
			// UNKNOWN message type received
			//----------------------------------------------------------
			logger.Printf(logger.ERROR, "[gns] Unhandled message of type (%d)\n", msg.Header().MsgType)
			continue
		}

		// send response
		if err := mc.Send(resp); err != nil {
			logger.Printf(logger.ERROR, "[gns] Failed to send response: %s\n", err.Error())
		}

	}
	// close client connection
	mc.Close()
}

// LookupNamecache
func (s *GNSService) LookupNamecache(query *Query) (block *GNSBlock, err error) {
	logger.Printf(logger.DBG, "[gns] LookupNamecache(%s)...\n", hex.EncodeToString(query.Key.Bits))

	// assemble Namecache request
	req := message.NewNamecacheLookupMsg(query.Key)
	req.Id = uint32(util.NextID())
	block = nil

	// get response from Namecache service
	var resp message.Message
	if resp, err = service.ServiceRequestResponse("gns", "Namecache", config.Cfg.Namecache.Endpoint, req); err != nil {
		return
	}

	// handle message depending on its type
	logger.Println(logger.DBG, "[gns] Handling response from Namecache service")
	switch m := resp.(type) {
	case *message.NamecacheLookupResultMsg:
		// check for matching IDs
		if m.Id != req.Id {
			logger.Println(logger.ERROR, "[gns] Got response for unknown ID")
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
			break
		}

		// assemble GNSBlock from message
		block = new(GNSBlock)
		block.Signature = m.Signature
		block.DerivedKey = m.DerivedKey
		sb := new(SignedBlockData)
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
	}
	return
}

// StoreNamecache
func (s *GNSService) StoreNamecache(query *Query, block *GNSBlock) error {
	logger.Println(logger.WARN, "[gns] StoreNamecache() not implemented yet!")
	return nil
}

// LookupDHT
func (s *GNSService) LookupDHT(query *Query) (block *GNSBlock, err error) {
	logger.Printf(logger.DBG, "[gns] LookupDHT(%s)...\n", hex.EncodeToString(query.Key.Bits))

	// assemble DHT request
	req := message.NewDHTClientGetMsg(query.Key)
	req.Id = uint64(util.NextID())
	req.ReplLevel = uint32(enums.DHT_GNS_REPLICATION_LEVEL)
	req.Type = uint32(enums.BLOCK_TYPE_GNS_NAMERECORD)
	req.Options = uint32(enums.DHT_RO_DEMULTIPLEX_EVERYWHERE)
	block = nil

	// get response from DHT service
	var resp message.Message
	if resp, err = service.ServiceRequestResponse("gns", "DHT", config.Cfg.DHT.Endpoint, req); err != nil {
		return
	}

	// handle message depending on its type
	logger.Println(logger.DBG, "[gns] Handling response from DHT service")
	switch m := resp.(type) {
	case *message.DHTClientResultMsg:
		// check for matching IDs
		if m.Id != req.Id {
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
		block = NewGNSBlock()
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
		if err = s.StoreNamecache(query, block); err != nil {
			logger.Printf(logger.ERROR, "[gns] can't store block in Namecache: %s\n", err.Error())
		}
	}
	return
}

// GetPrivateZone
func (s *GNSService) GetPrivateZone(name string) (*ed25519.PublicKey, error) {
	return nil, nil
}
