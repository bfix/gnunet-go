package gns

import (
	"encoding/hex"
	"io"
	"time"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
	"gnunet/config"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service"
	"gnunet/transport"
	"gnunet/util"
)

//----------------------------------------------------------------------
// "GNUnet Name System" service implementation
//----------------------------------------------------------------------

// GNSService
type GNSService struct {
}

// NewGNSService
func NewGNSService() service.Service {
	return &GNSService{}
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
			resp = message.NewGNSLookupResultMsg(m.Id)
			// perform lookup on block (either from Namecache or DHT)
			block, err := s.Lookup(m)
			if err != nil {
				logger.Printf(logger.ERROR, "gns.Lookup(): Failed to lookup query: %s\n", err.Error())
				break
			}
			// handle block
			if block != nil {
				logger.Printf(logger.DBG, "[gns] Received block: %v\n", block)
				switch int(m.Type) {
				case enums.GNS_TYPE_DNS_A:
					logger.Println(logger.DBG, "[gns] Lookup type: DNS_A")
				}
			}

		default:
			//----------------------------------------------------------
			// UNKNOWN message type received
			//----------------------------------------------------------
			logger.Printf(logger.ERROR, "gns.Lookup(): Unhandled message of type (%d)\n", msg.Header().MsgType)
			continue
		}

		// send response
		if err := mc.Send(resp); err != nil {
			logger.Printf(logger.ERROR, "gns.Lookup(): Failed to send response: %s\n", err.Error())
		}

	}
	// close client connection
	mc.Close()
}

// Lookup handles GNU_LOOKUP messages
func (s *GNSService) Lookup(m *message.GNSLookupMsg) (block *GNSBlock, err error) {
	// create DHT/NAMECACHE query
	pkey := ed25519.NewPublicKeyFromBytes(m.Zone)
	label := m.GetName()
	query := QueryFromPublickeyDerive(pkey, label)

	// try namecache lookup first
	if block, err = s.LookupNamecache(query, pkey, label); err != nil {
		logger.Printf(logger.ERROR, "gns.Lookup(namecache): %s\n", err.Error())
		block = nil
		return
	}
	if block == nil {
		logger.Println(logger.DBG, "gns.Lookup(namecache): no block found")
		// if int(m.Options) == enums.GNS_LO_DEFAULT {
		// get the block from the DHT
		if block, err = s.LookupDHT(query, pkey, label); err != nil || block == nil {
			if err != nil {
				logger.Printf(logger.ERROR, "gns.Lookup(dht): %s\n", err.Error())
				block = nil
			} else {
				logger.Println(logger.DBG, "gns.Lookup(dht): no block found")
			}
			// lookup fails completely -- no result
		}
		//}
	}
	return
}

// LookupNamecache
func (s *GNSService) LookupNamecache(query *crypto.HashCode, zoneKey *ed25519.PublicKey, label string) (block *GNSBlock, err error) {
	logger.Printf(logger.DBG, "[gns] LookupNamecache(%s)...\n", hex.EncodeToString(query.Bits))

	// assemble Namecache request
	req := message.NewNamecacheLookupMsg(query)
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
			return
		}
		// check if block was found
		if len(m.EncData) == 0 {
			logger.Println(logger.DBG, "[gns] block not found in namecache")
			return
		}
		// check if record has expired
		if m.Expire > 0 && int64(m.Expire) < time.Now().Unix() {
			logger.Printf(logger.ERROR, "[gns] block expired at %s\n", util.Timestamp(m.Expire))
			return
		}

		// assemble the GNSBlock from message
		block = new(GNSBlock)
		block.Signature = m.Signature
		block.DerivKey = m.DerivedKey
		sb := new(SignedBlockData)
		sb.Purpose = new(crypto.SignaturePurpose)
		sb.Purpose.Purpose = enums.SIG_GNS_RECORD_SIGN
		sb.Purpose.Size = uint32(16 + len(m.EncData))
		sb.Expire = m.Expire
		sb.Data = m.EncData
		block.Block = sb

		// decrypt payload
		if sb.Data, err = DecryptBlock(sb.Data, zoneKey, label); err != nil {
			logger.Printf(logger.ERROR, "[gns] Block can't be decrypted: %s\n", err.Error())
		}

		//		pkey := ed25519.NewPublicKeyFromBytes(m.DerivedKey)
		//		var sig *ed25519.EcSignature
		//		if sig, err = ed25519.NewEcSignatureFromBytes(m.Signature); err != nil {
		//			logger.Printf(logger.ERROR, "[gns] Failed to read signature: %s\n", err.Error())
		//			return
		//		}
		//		var ok bool
		//		if err = crypto.EcVerify(data, sig, pkey); err != nil {
		//			return
		//		}
	}
	return
}

// LookupDHT
func (s *GNSService) LookupDHT(query *crypto.HashCode, zoneKey *ed25519.PublicKey, label string) (block *GNSBlock, err error) {
	logger.Printf(logger.DBG, "[gns] LookupDHT(%s)...\n", hex.EncodeToString(query.Bits))

	// assemble DHT request
	req := message.NewDHTClientGetMsg(query)
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
			return
		}
		// check if block was found
		if len(m.Data) == 0 {
			logger.Println(logger.DBG, "[gns] block not found in DHT")
			return
		}
		// check if record has expired
		if m.Expire > 0 && int64(m.Expire) < time.Now().Unix() {
			logger.Printf(logger.ERROR, "[gns] block expired at %s\n", util.Timestamp(m.Expire))
			return
		}
	}
	return
}
