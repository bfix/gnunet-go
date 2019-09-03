package gns

import (
	"encoding/hex"

	"github.com/bfix/gospel/logger"
	"gnunet/config"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service"
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
	var result message.Message = nil
	switch m := msg.(type) {
	case *message.GNSLookupMsg:
		logger.Println(logger.INFO, "[gns] Lookup request received.")
		result = s.Lookup(m)
	default:
	}
	if err := s.sendMsg(result); err != nil {
		logger.Printf(logger.ERROR, "gns.Lookup(): Failed to send message: %s\n", err.Error())
	}
	return
}

// Lookup handles GNU_LOOKUP messages
func (s *GNSService) Lookup(m *message.GNSLookupMsg) message.Message {
	// create DHT/NAMECACHE query
	pkey := crypto.NewPublicKey(m.Zone)
	query := QueryFromPublickeyDerive(pkey, m.GetName())

	// try namecache lookup first
	result, err := s.LookupNamecache(query)
	if err != nil {
		logger.Printf(logger.ERROR, "gns.Lookup(): %s\n", err.Error())
		return result
	}

	switch int(m.Options) {
	case enums.GNS_LO_DEFAULT:
		logger.Println(logger.DBG, "[gns] Lookup location: Cache, DHT")
	case enums.GNS_LO_NO_DHT:
		logger.Println(logger.DBG, "[gns] Lookup location: Cache only")
	case enums.GNS_LO_LOCAL_MASTER:
		logger.Println(logger.DBG, "[gns] Lookup location: Master in cache; Cache, DHT for rest")
	}
	switch int(m.Type) {
	case enums.GNS_TYPE_DNS_A:
		logger.Println(logger.DBG, "[gns] Lookup type: DNS_A")
	}
	return result
}

// LookupNamecache
func (s *GNSService) LookupNamecache(query *crypto.HashCode) (result *message.GNSLookupResultMsg, err error) {
	logger.Printf(logger.DBG, "[gns] LookupNamecache(%s)...\n", hex.EncodeToString(query.Bits))

	// assemble Namecache request
	req := message.NewNamecacheLookupMsg(query)
	result = nil

	// client-connect to the service
	var cl *service.Client
	if cl, err = service.NewClient(config.Cfg.Namecache.Endpoint); err != nil {
		return
	}
	// send request
	if err = cl.SendRequest(req); err != nil {
		return
	}
	// wait for a single response, then close the connection
	var resp message.Message
	if resp, err = cl.ReceiveResponse(); err != nil {
		return
	}
	if err = cl.Close(); err != nil {
		return
	}

	// handle message depending on its type
	switch m := resp.(type) {
	case *message.NamecacheLookupResultMsg:

	}
	// return response
	return result, nil
}
