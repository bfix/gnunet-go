package transport

import (
	"net"
	"strings"
)

////////////////////////////////////////////////////////////////////////
// Generic network-based Channel

// NetworkChannel
type NetworkChannel struct {
	network string
	conn    net.Conn
}

// NewNetworkChannel
func NewNetworkChannel(netw string) Channel {
	return &NetworkChannel{
		network: netw,
		conn:    nil,
	}
}

// Clone
func (c *NetworkChannel) Clone() Channel {
	return NewNetworkChannel(c.network)
}

// Open
func (c *NetworkChannel) Open(spec string) (err error) {
	parts := strings.Split(spec, "+")
	// check for correct protocol
	if parts[0] != c.network {
		return ErrChannelNotImplemented
	}
	// open connection
	c.conn, err = net.Dial(c.network, parts[1])
	return
}

// Close
func (c *NetworkChannel) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return ErrChannelNotOpened
}

// Read
func (c *NetworkChannel) Read(buf []byte) (int, error) {
	if c.conn == nil {
		return 0, ErrChannelNotOpened
	}
	return c.conn.Read(buf)
}

// Write
func (c *NetworkChannel) Write(buf []byte) (int, error) {
	if c.conn == nil {
		return 0, ErrChannelNotOpened
	}
	return c.conn.Write(buf)
}

////////////////////////////////////////////////////////////////////////
// Generic network-based ChannelServer

// NetworkChannelServer
type NetworkChannelServer struct {
	network  string
	listener net.Listener
}

// NewNetworkChannelServer
func NewNetworkChannelServer(netw string) ChannelServer {
	return &NetworkChannelServer{
		network:  netw,
		listener: nil,
	}
}

// Clone
func (c *NetworkChannelServer) Clone() ChannelServer {
	return NewNetworkChannelServer(c.network)
}

// Open
func (s *NetworkChannelServer) Open(spec string, hdlr chan<- Channel) (err error) {
	// check for correct protocol
	if !strings.HasPrefix(spec, s.network+"+") {
		return ErrChannelNotImplemented
	}
	// create listener
	if s.listener, err = net.Listen(s.network, spec[len(s.network)+1:]); err != nil {
		return
	}
	// run go routine to handle channel requests from clients
	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				// signal failure and terminate
				hdlr <- nil
				break
			}
			// send channel to handler
			hdlr <- &NetworkChannel{
				network: s.network,
				conn:    conn,
			}
		}
		if s.listener != nil {
			s.listener.Close()
		}
	}()

	return nil
}

// Close
func (s *NetworkChannelServer) Close() error {
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}
