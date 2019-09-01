package gns

import (
	"github.com/bfix/gospel/logger"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service"
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

// HandleMsg for GNS specific messages that are delegated to
// service methods.
func (s *GNSService) HandleMsg(msg message.Message) {
	switch m := msg.(type) {
	case *message.GNSLookupMsg:
		logger.Println(logger.INFO, "[gns] Lookup request received.")
		s.Lookup(m)
	}
}

// Lookup handles GNU_LOOKUP messages
func (s *GNSService) Lookup(m *message.GNSLookupMsg) {
	switch int(m.Options) {
	case enums.GNS_LO_DEFAULT:
		logger.Println(logger.DBG, "[gns] Lookup location: Cache, DHT")
	case enums.GNS_LO_NO_DHT:
		logger.Println(logger.DBG, "[gns] Lookup location: Cache only")
	case enums.GNS_LO_LOCAL_MASTER:
		logger.Println(logger.DBG, "[gns] Lookup location: Master in cache; Cache, DHT for rest")
	}
	switch int(m.Type) {
	case enums.GNS_TYPE_PKEY:
		logger.Println(logger.DBG, "[gns] Lookup type: PKEY")
	}
}
