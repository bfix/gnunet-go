package gns

import (
	"encoding/hex"
	"time"

	"github.com/bfix/gospel/logger"
	"gnunet/config"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service"
	"gnunet/util"
)

//----------------------------------------------------------------------
// "GNUnet Name System" service implementation
//----------------------------------------------------------------------

// GNSService
type GNSService struct {
	sendMsg func(message.Message) error
}

// NewGNSService
func NewGNSService() service.Service {
	return &GNSService{
		sendMsg: service.SendMsgUndefined,
	}
}

// Start the GNS service
func (s *GNSService) Start(spec string) error {
	return nil
}

// Stop the GNS service
func (s *GNSService) Stop() error {
	return nil
}

// SetSendMsg
func (s *GNSService) SetSendMsg(hdlr func(message.Message) error) {
	s.sendMsg = hdlr
}

// HandleMsg for GNS specific messages that are delegated to
// service methods.
func (s *GNSService) HandleMsg(msg message.Message) {
	// prepare result message
	resp := message.NewGNSLookupResultMsg()

	// perform lookup
	switch m := msg.(type) {
	case *message.GNSLookupMsg:
		logger.Println(logger.INFO, "[gns] Lookup request received.")
		// set request Id in response
		resp.Id = m.Id
		// perform lookup on block
		_, err := s.Lookup(m)
		if err != nil {
			logger.Printf(logger.ERROR, "gns.Lookup(): Failed to lookup query: %s\n", err.Error())
			break
		}
	default:
		logger.Printf(logger.ERROR, "gns.Lookup(): Unhandled message of type (%d)\n", msg.Header().MsgType)
	}

	// send response
	if err := s.sendMsg(resp); err != nil {
		logger.Printf(logger.ERROR, "gns.Lookup(): Failed to send response: %s\n", err.Error())
	}
	return
}

// Lookup handles GNU_LOOKUP messages
func (s *GNSService) Lookup(m *message.GNSLookupMsg) (block []byte, err error) {
	// create DHT/NAMECACHE query
	pkey := crypto.NewPublicKeyFromBytes(m.Zone)
	query := QueryFromPublickeyDerive(pkey, m.GetName())

	// try namecache lookup first
	if block, err = s.LookupNamecache(query); err != nil {
		logger.Printf(logger.ERROR, "gns.Lookup(namecache): %s\n", err.Error())
		block = nil
		return
	}
	if block == nil {
		logger.Println(logger.DBG, "gns.Lookup(namecache): no block found")
		if int(m.Options) == enums.GNS_LO_DEFAULT {
			// get the block from the DHT
			if block, err = s.LookupDHT(query); err != nil || block == nil {
				if err != nil {
					logger.Printf(logger.ERROR, "gns.Lookup(dht): %s\n", err.Error())
					block = nil
				} else {
					logger.Println(logger.DBG, "gns.Lookup(dht): no block found")
				}
				// lookup fails completely -- no result
				return
			}
		}
	}

	switch int(m.Type) {
	case enums.GNS_TYPE_DNS_A:
		logger.Println(logger.DBG, "[gns] Lookup type: DNS_A")
	}
	return nil, nil
}

// LookupNamecache
func (s *GNSService) LookupNamecache(query *crypto.HashCode) (result []byte, err error) {
	logger.Printf(logger.DBG, "[gns] LookupNamecache(%s)...\n", hex.EncodeToString(query.Bits))

	// assemble Namecache request
	req := message.NewNamecacheLookupMsg(query)
	req.Id = uint32(util.NextID())
	result = nil

	// client-connect to the service
	logger.Println(logger.DBG, "[gns] Connect to Namecache service")
	var cl *service.Client
	if cl, err = service.NewClient(config.Cfg.Namecache.Endpoint); err != nil {
		return
	}
	// send request
	logger.Println(logger.DBG, "[gns] Sending request to Namecache service")
	if err = cl.SendRequest(req); err != nil {
		return
	}
	// wait for a single response, then close the connection
	logger.Println(logger.DBG, "[gns] Waiting for response from Namecache service")
	var resp message.Message
	if resp, err = cl.ReceiveResponse(); err != nil {
		return
	}
	logger.Println(logger.DBG, "[gns] Closing connection to Namecache service")
	if err = cl.Close(); err != nil {
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
		// check if data has expired
		if int64(m.Expire) < time.Now().Unix() {
			logger.Printf(logger.ERROR, "[gns] block expired at %s\n", util.Timestamp(m.Expire))
			return
		}
		// decrypt payload
		pkey := crypto.NewPublicKeyFromBytes(m.DerivedKey)
		sig := crypto.NewSignatureFromBytes(m.Signature, false)
		if result, err = s.DecryptBlock(pkey, sig, m.EncData); err != nil {
			logger.Printf(logger.ERROR, "[gns] Block can't be decrypted: %s\n", err.Error())
		}
	}
	return
}

// LookupDHT
func (s *GNSService) LookupDHT(query *crypto.HashCode) (result []byte, err error) {
	logger.Printf(logger.DBG, "[gns] LookupDHT(%s)...\n", hex.EncodeToString(query.Bits))

	// assemble DHT request
	req := message.NewDHTClientGetMsg(query)
	req.Id = uint64(util.NextID())
	result = nil

	// client-connect to the service
	logger.Println(logger.DBG, "[gns] Connect to DHT service")
	var cl *service.Client
	if cl, err = service.NewClient(config.Cfg.DHT.Endpoint); err != nil {
		return
	}
	// send request
	logger.Println(logger.DBG, "[gns] Sending request to DHT service")
	if err = cl.SendRequest(req); err != nil {
		return
	}
	// wait for a single response, then close the connection
	logger.Println(logger.DBG, "[gns] Waiting for response from DHT service")
	var resp message.Message
	if resp, err = cl.ReceiveResponse(); err != nil {
		return
	}
	logger.Println(logger.DBG, "[gns] Closing connection to DHT service")
	if err = cl.Close(); err != nil {
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
		// check if data has expired
		if int64(m.Expire) < time.Now().Unix() {
			logger.Printf(logger.ERROR, "[gns] block expired at %s\n", util.Timestamp(m.Expire))
			return
		}
		// decrypt payload
		if result, err = s.DecryptBlock(nil, nil, m.Data); err != nil {
			logger.Printf(logger.ERROR, "[gns] Block can't be decrypted: %s\n", err.Error())
		}
	}
	return
}
