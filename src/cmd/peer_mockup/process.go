package main

import (
	"errors"
	"fmt"

	"gnunet/core"
	"gnunet/crypto"
	"gnunet/message"
	"gnunet/transport"
	"gnunet/util"
)

func process(ch *transport.MsgChannel, from, to *core.Peer) (err error) {
	// create a new connection instance
	c := transport.NewConnection(ch, from, to)
	defer c.Close()

	// read and push next message
	in := make(chan message.Message)
	go func() {
		for {
			msg, _, err := c.Receive()
			if err != nil {
				fmt.Printf("Receive: %s\n", err.Error())
				return
			}
			in <- msg
		}
	}()

	// are we initiating the connection?
	init := (from == p)
	if init {
		c.Send(message.NewTransportTcpWelcomeMsg(p.GetID()))
	}

	// remember peer addresses (only ONE!)
	pAddr := p.GetAddressList()[0]
	tAddr := t.GetAddressList()[0]

	send := make(map[uint16]bool)
	//received := make(map[uint16]bool)
	pending := make(map[uint16]message.Message)

	// process loop
	for {
		select {
		case m := <-in:
			switch msg := m.(type) {

			case *message.TransportTcpWelcomeMsg:
				if init {
					c.Send(message.NewHelloMsg(p.GetID()))
					c.Send(message.NewTransportPingMsg(t.GetID(), tAddr))
				} else {
					c.Send(message.NewTransportTcpWelcomeMsg(p.GetID()))
				}

			case *message.HelloMsg:

			case *message.TransportPingMsg:
				mOut := message.NewTransportPongMsg(msg.Challenge, pAddr)
				if err := mOut.Sign(p.PrvKey()); err != nil {
					return err
				}
				c.Send(mOut)

			case *message.TransportPongMsg:
				rc, err := msg.Verify(t.PubKey())
				if err != nil {
					return err
				}
				if !rc {
					return errors.New("PONG verification failed")
				}
				send[message.TRANSPORT_PONG] = true
				if mOut, ok := pending[message.TRANSPORT_SESSION_SYN]; ok {
					c.Send(mOut)
				}

			case *message.SessionSynMsg:
				mOut := message.NewSessionSynAckMsg(msg.Timestamp)
				if send[message.TRANSPORT_PONG] {
					c.Send(mOut)
				} else {
					pending[message.TRANSPORT_SESSION_SYN] = mOut
				}

			case *message.SessionQuotaMsg:
				c.SetBandwidth(msg.Quota)

			case *message.SessionAckMsg:

			case *message.SessionKeepAliveMsg:
				c.Send(message.NewSessionKeepAliveRespMsg(msg.Nonce))

			case *message.EphemeralKeyMsg:
				rc, err := msg.Verify(t.PubKey())
				if err != nil {
					return err
				}
				if !rc {
					return errors.New("EPHKEY verification failed")
				}
				t.SetEphKeyMsg(msg)
				c.Send(p.EphKeyMsg())
				secret := crypto.SharedSecret(p.EphPrvKey(), t.EphKeyMsg().Public())
				c.SharedSecret(util.Clone(secret.Bits[:]))

			default:
				fmt.Printf("!!! %v\n", msg)
			}
		default:
		}
	}
	return nil
}
