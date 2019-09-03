package service

import (
	"fmt"
	"io"

	"github.com/bfix/gospel/logger"
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
	SetSendMsg(hdlr func(message.Message) error)
	Stop() error
}

// ServiceImpl is an implementation of generic service functionality.
type ServiceImpl struct {
	impl    Service
	hdlr    chan transport.Channel
	srvc    transport.ChannelServer
	name    string
	running bool
}

// NewServiceImpl instantiates a new ServiceImpl object.
func NewServiceImpl(name string, srv Service) *ServiceImpl {
	return &ServiceImpl{
		impl:    srv,
		hdlr:    make(chan transport.Channel),
		srvc:    nil,
		name:    name,
		running: false,
	}
}

// Start a service
func (si *ServiceImpl) Start(spec string) (err error) {
	// check if we are already running
	if si.running {
		logger.Printf(logger.ERROR, "Service '%s' already running.\n", si.name)
		return fmt.Errorf("service already running")
	}

	// start channel server
	logger.Printf(logger.DBG, "[%s] Service starting.\n", si.name)
	if si.srvc, err = transport.NewChannelServer(spec, si.hdlr); err != nil {
		return
	}
	si.running = true

	// handle clients
	go func() {
	loop:
		for si.running {
			select {
			case in := <-si.hdlr:
				if in == nil {
					logger.Printf(logger.DBG, "[%s] Listener terminated.\n", si.name)
					break loop
				}
				switch ch := in.(type) {
				case transport.Channel:
					logger.Printf(logger.DBG, "[%s] Client connected.\n", si.name)
					go si.Serve(ch)
				}
			default:
			}
		}
		logger.Printf(logger.DBG, "[%s] Service closing.\n", si.name)
		si.srvc.Close()
		si.running = false
	}()

	return si.impl.Start(spec)
}

// Stop a service
func (si *ServiceImpl) Stop() error {
	if !si.running {
		logger.Printf(logger.WARN, "Service '%s' not running.\n", si.name)
		return fmt.Errorf("service not running")
	}
	si.running = false
	logger.Printf(logger.DBG, "[%s] Service terminating.\n", si.name)

	return si.impl.Stop()
}

// Serve a client channel.
func (si *ServiceImpl) Serve(ch transport.Channel) {
	mc := transport.NewMsgChannel(ch)
	for {
		msg, err := mc.Receive()
		if err != nil {
			if err == io.EOF {
				logger.Printf(logger.INFO, "[%s] Client channel closed.\n", si.name)
			} else {
				logger.Printf(logger.ERROR, "[%s] Message-receive failed: %s\n", si.name, err.Error())
			}
			break
		}
		logger.Printf(logger.INFO, "[%s] Received msg: %v\n", si.name, msg)
		si.impl.HandleMsg(msg)
	}
	ch.Close()
}

// SendMsgUndefined
func SendMsgUndefined(m message.Message) error {
	return fmt.Errorf("gns.Lookup(): No sender for message: %v\n", m)
}
