package gns

import (
	"github.com/bfix/gospel/logger"
	"gnunet/message"
	"gnunet/service"
)

var (
	DHT_GNS_REPLICATION_LEVEL = 10
)

// "GNUnet Name System" service
type GNSService struct {
}

func NewGNSService() service.Service {
	return &GNSService{}
}

// Start GNS service
func (s *GNSService) Start(spec string) error {
	return nil
}

// Stop a service
func (s *GNSService) Stop() error {
	return nil
}

// HandleMsg for GNS specific messages.
func (s *GNSService) HandleMsg(msg message.Message) {
	logger.Printf(logger.DBG, "GNS<<: %v\n", msg)
}
