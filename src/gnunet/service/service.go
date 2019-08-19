package transport

import (
	"fmt"
	"net"
	"os"
)

// Service is an interface for GNUnet services.
//
type Service interface {
	Start(network, addr string) error
	Stop() error
}

type ServiceImpl struct {
}

// NewSocketServer runs a new socket listener for a GNUnet service.
// The channels are used to pass control and status/error messages
// between the socket server (A) and the enclosing service (B):
//    out: A->B: error -- any error occurring in the socker server process
//               net.Conn -- a new client connection established
//               bool -- socket server terminated
//	  in:  B->A: bool -- terminate socket server (any value)
func NewSocketServer(addr string, in <-chan interface{}, out chan<- interface{}) error {

	// create socket for client connections.
	listener, err := net.Listen("unix", addr)
	if err != nil {
		return err
	}

	// run the message handler in separate routine
	go func() {
		for {
			select {
			case cmd := <-in:
				switch cmd.(type) {
				case bool:
					fmt.Println("TERMINATING")
					listener.Close()
					if err := os.RemoveAll(addr); err != nil {
						out <- err
					}
					out <- true
					break
				}
			}
		}
	}()

	// run the listener in a separate routine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				out <- err
			} else {
				out <- conn
			}
		}
	}()

	return nil
}
