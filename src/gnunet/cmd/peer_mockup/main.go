package main

import (
	"errors"
	"flag"
	"fmt"

	"gnunet/core"
	"gnunet/crypto"
	"gnunet/message"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/concurrent"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
)

var (
	local  *core.Peer // local peer (with private key)
	remote *core.Peer // remote peer
	sig    = concurrent.NewSignaller()
)

func main() {
	// handle command line arguments
	var (
		asServer bool
		err      error
		ch       transport.Channel
	)
	flag.BoolVar(&asServer, "s", false, "accept incoming connections")
	flag.Parse()

	// setup peer instances from static data
	if err = setupPeers(false); err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("======================================================================")
	fmt.Println("GNUnet peer mock-up (EXPERIMENTAL)     (c) 2018,2019 by Bernd Fix, >Y<")
	fmt.Printf("    Identity '%s'\n", local.GetIDString())
	fmt.Printf("    [%s]\n", local.GetID().String())
	fmt.Println("======================================================================")

	if asServer {
		// run as server
		fmt.Println("Waiting for connections...")
		hdlr := make(chan transport.Channel)
		go func() {
			for {
				select {
				case ch = <-hdlr:
					mc := transport.NewMsgChannel(ch)
					if err = process(mc, remote, local); err != nil {
						logger.Println(logger.ERROR, err.Error())
					}
				}
			}
		}()
		_, err = transport.NewChannelServer("tcp+0.0.0.0:2086", hdlr)
	} else {
		// connect to peer
		fmt.Println("Connecting to target peer")
		if ch, err = transport.NewChannel("tcp+172.17.0.5:2086"); err != nil {
			logger.Println(logger.ERROR, err.Error())
		}
		mc := transport.NewMsgChannel(ch)
		err = process(mc, local, remote)
	}
	if err != nil {
		fmt.Println(err)
	}
}

func setupPeers(rnd bool) (err error) {

	//------------------------------------------------------------------
	// create local peer
	//------------------------------------------------------------------
	secret := []byte{
		0x78, 0xde, 0xcf, 0xc0, 0x26, 0x9e, 0x62, 0x3d,
		0x17, 0x24, 0xe6, 0x1b, 0x98, 0x25, 0xec, 0x2f,
		0x40, 0x6b, 0x1e, 0x39, 0xa5, 0x19, 0xac, 0x9b,
		0xb2, 0xdd, 0xf4, 0x6c, 0x12, 0x83, 0xdb, 0x86,
	}
	if rnd {
		util.RndArray(secret)
	}
	local, err = core.NewPeer(secret, true)
	if err != nil {
		return
	}
	addr, _ := data.Marshal(util.NewIPAddress([]byte{172, 17, 0, 6}, 2086))
	local.AddAddress(util.NewAddress("tcp", addr))

	//------------------------------------------------------------------
	// create remote peer
	//------------------------------------------------------------------
	id := []byte{
		0x92, 0xdc, 0xbf, 0x39, 0x40, 0x2d, 0xc6, 0x3c,
		0x97, 0xa6, 0x81, 0xe0, 0xfc, 0xd8, 0x7c, 0x74,
		0x17, 0xd3, 0xa3, 0x8c, 0x52, 0xfd, 0xe0, 0x49,
		0xbc, 0xd0, 0x1c, 0x0a, 0x0b, 0x8c, 0x02, 0x51,
	}
	remote, err = core.NewPeer(id, false)
	if err != nil {
		return
	}
	addr, _ = data.Marshal(util.NewIPAddress([]byte{172, 17, 0, 5}, 2086))
	remote.AddAddress(util.NewAddress("tcp", addr))
	return
}

func process(ch *transport.MsgChannel, from, to *core.Peer) (err error) {
	// create a new connection instance
	c := transport.NewConnection(ch, from, to)
	defer c.Close()

	// read and push next message
	in := make(chan message.Message)
	go func() {
		for {
			msg, err := c.Receive(sig)
			if err != nil {
				fmt.Printf("Receive: %s\n", err.Error())
				return
			}
			in <- msg
		}
	}()

	// are we initiating the connection?
	init := (from == local)
	if init {
		peerid := local.GetID()
		c.Send(message.NewTransportTCPWelcomeMsg(peerid), sig)
	}

	// remember peer addresses (only ONE!)
	pAddr := local.GetAddressList()[0]
	tAddr := remote.GetAddressList()[0]

	send := make(map[uint16]bool)
	//received := make(map[uint16]bool)
	pending := make(map[uint16]message.Message)

	// process loop
	for {
		select {
		case m := <-in:
			switch msg := m.(type) {

			case *message.TransportTCPWelcomeMsg:
				peerid := local.GetID()
				if init {
					c.Send(message.NewHelloMsg(peerid), sig)
					target := remote.GetID()
					c.Send(message.NewTransportPingMsg(target, tAddr), sig)
				} else {
					c.Send(message.NewTransportTCPWelcomeMsg(peerid), sig)
				}

			case *message.HelloMsg:

			case *message.TransportPingMsg:
				mOut := message.NewTransportPongMsg(msg.Challenge, pAddr)
				if err := mOut.Sign(local.PrvKey()); err != nil {
					return err
				}
				c.Send(mOut, sig)

			case *message.TransportPongMsg:
				rc, err := msg.Verify(remote.PubKey())
				if err != nil {
					return err
				}
				if !rc {
					return errors.New("PONG verification failed")
				}
				send[message.TRANSPORT_PONG] = true
				if mOut, ok := pending[message.TRANSPORT_SESSION_SYN]; ok {
					c.Send(mOut, sig)
				}

			case *message.SessionSynMsg:
				mOut := message.NewSessionSynAckMsg()
				mOut.Timestamp = msg.Timestamp
				if send[message.TRANSPORT_PONG] {
					c.Send(mOut, sig)
				} else {
					pending[message.TRANSPORT_SESSION_SYN] = mOut
				}

			case *message.SessionQuotaMsg:
				c.SetBandwidth(msg.Quota)

			case *message.SessionAckMsg:

			case *message.SessionKeepAliveMsg:
				c.Send(message.NewSessionKeepAliveRespMsg(msg.Nonce), sig)

			case *message.EphemeralKeyMsg:
				rc, err := msg.Verify(remote.PubKey())
				if err != nil {
					return err
				}
				if !rc {
					return errors.New("EPHKEY verification failed")
				}
				remote.SetEphKeyMsg(msg)
				c.Send(local.EphKeyMsg(), sig)
				secret := crypto.SharedSecret(local.EphPrvKey(), remote.EphKeyMsg().Public())
				c.SharedSecret(util.Clone(secret.Bits[:]))

			default:
				fmt.Printf("!!! %v\n", msg)
			}
		default:
		}
	}
	return nil
}
