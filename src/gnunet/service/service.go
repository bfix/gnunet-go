package service

import (
	"fmt"

	"gnunet/message"
	"gnunet/transport"
)

// Service is an interface for GNUnet services. Every service has one channel
// end-point it listens to for incoming channel requests (network-based
// channels established by service clients). The end-point is specified in
// Channel semantics in the specification string.
type Service interface {
	Start(spec string) error
	HandleMsg(msg message.Message)
	Stop() error
}

// ServiceImpl is an implementation of generic service functionality.
type ServiceImpl struct {
	hdlr    chan transport.Channel
	srvc    transport.ChannelServer
	running bool
}

// NewServiceImpl instantiates a new ServiceImpl object.
func NewServiceImpl() *ServiceImpl {
	return &ServiceImpl{
		hdlr:    make(chan transport.Channel),
		srvc:    nil,
		running: false,
	}
}

// Start a service
func (si *ServiceImpl) Start(spec string) (err error) {
	// check if we are already running
	if si.running {
		return fmt.Errorf("service already running")
	}

	// start channel server
	if si.srvc, err = transport.NewChannelServer(spec, si.hdlr); err != nil {
		return
	}
	si.running = true

	// handle clients
	go func() {
		for si.running {
			select {
			case in := <-si.hdlr:
				if in == nil {
					break
				}
				switch ch := in.(type) {
				case transport.Channel:
					go si.Serve(ch)
				}
			}
		}
		si.srvc.Close()
		si.running = false
	}()
	return nil
}

// Stop a service
func (si *ServiceImpl) Stop() (err error) {
	if !si.running {
		err = fmt.Errorf("service not running")
	}
	si.running = false
	return
}

// Serve a client channel.
func (si *ServiceImpl) Serve(ch transport.Channel) {
	mc := transport.NewMsgChannel(ch)
	for {
		msg, _, err := mc.Receive()
		if err != nil {
			break
		}
		si.HandleMsg(msg)
	}
	ch.Close()
}

// HandleMsg is implemented by specific GNUnet services.
func (si *ServiceImpl) HandleMsg(msg message.Message) {
}
