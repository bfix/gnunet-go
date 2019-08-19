package gns

import (
	"log"

	"gnunet/message"
	"gnunet/service"
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
	log.Printf("GNS<<: %v\n", msg)
}
