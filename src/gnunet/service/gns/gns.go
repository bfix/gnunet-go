package gns

import (
	"gnunet/message"
	"gnunet/service"
)

// "GNUnet Name System" service
type GNSService struct {
	service.ServiceImpl
}

// HandleMsg for GNS specific messages.
func (s *GNSService) HandleMsg(msg message.Message) {
}
