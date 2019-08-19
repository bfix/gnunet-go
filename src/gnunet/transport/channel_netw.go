package transport

import (
	"net"
	"reflect"
	"strings"
)

////////////////////////////////////////////////////////////////////////
// Generic network-based Channel

// NetworkChannel
type NetworkChannel struct {
	network string
	conn    net.Conn
}

// Open
func (c *NetworkChannel) Open(spec string) (err error) {
	// check for correct protocol
	if !strings.HasPrefix(spec, c.network+"+") {
		return ErrChannelNotImplemented
	}
	// open connection
	c.conn, err = net.Dial(c.network, spec[len(c.network)+1:])
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

////////////////////////////////////////////////////////////////////////
// Protocol-specific network-based Channel

//----------------------------------------------------------------------
// TCP
//----------------------------------------------------------------------

type TCPChannel struct {
	NetworkChannel
}

func TCPChannelType() reflect.Type {
	ch := new(TCPChannel)
	ch.network = "tcp"
	return reflect.TypeOf(ch)
}

type TCPChannelServer struct {
	NetworkChannelServer
}

func TCPChannelServerType() reflect.Type {
	ch := new(TCPChannelServer)
	ch.network = "tcp"
	return reflect.TypeOf(ch)
}

//----------------------------------------------------------------------
// UDP
//----------------------------------------------------------------------

type UDPChannel struct {
	NetworkChannel
}

func UDPChannelType() reflect.Type {
	ch := new(UDPChannel)
	ch.network = "udp"
	return reflect.TypeOf(ch)
}

type UDPChannelServer struct {
	NetworkChannelServer
}

func UDPChannelServerType() reflect.Type {
	ch := new(UDPChannelServer)
	ch.network = "udp"
	return reflect.TypeOf(ch)
}

//----------------------------------------------------------------------
// Unix Domain Socket
//----------------------------------------------------------------------

type UDSChannel struct {
	NetworkChannel
}

func UDSChannelType() reflect.Type {
	ch := new(UDSChannel)
	ch.network = "unix"
	return reflect.TypeOf(ch)
}

type UDSChannelServer struct {
	NetworkChannelServer
}

func UDSChannelServerType() reflect.Type {
	ch := new(UDSChannelServer)
	ch.network = "unix"
	return reflect.TypeOf(ch)
}
