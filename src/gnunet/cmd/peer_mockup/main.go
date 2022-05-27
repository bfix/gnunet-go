package main

import (
	"errors"
	"flag"
	"fmt"

	"gnunet/config"
	"gnunet/core"
	"gnunet/crypto"
	"gnunet/message"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/concurrent"
	"github.com/bfix/gospel/logger"
)

var (
	// configuration for local node
	localCfg = &config.NodeConfig{
		PrivateSeed: "YGoe6XFH3XdvFRl+agx9gIzPTvxA229WFdkazEMdcOs=",
		Endpoints: []string{
			"r5n+ip+udp://127.0.0.1:6666",
		},
	}
	remoteCfg = "3GXXMNb5YpIUO7ejIR2Yy0Cf5texuLfDjHkXcqbPxkc="

	local      *core.Peer              // local peer (with private key)
	remote     *core.Peer              // remote peer
	remoteAddr = "tcp+172.17.0.5:2086" // network address of remote peer
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

	// setup peer instances
	if local, err = core.NewLocalPeer(localCfg); err != nil {
		fmt.Println("local failed: " + err.Error())
		return
	}
	if remote, err = core.NewPeer(remoteCfg); err != nil {
		fmt.Println("remote failed: " + err.Error())
		return
	}

	fmt.Println("======================================================================")
	fmt.Println("GNUnet peer mock-up (EXPERIMENTAL)     (c) 2018-2022 by Bernd Fix, >Y<")
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
		if ch, err = transport.NewChannel(remoteAddr); err != nil {
			logger.Println(logger.ERROR, err.Error())
		}
		mc := transport.NewMsgChannel(ch)
		err = process(mc, local, remote)
	}
	if err != nil {
		fmt.Println(err)
	}
}

// process never terminates; it is used for protocol exploration only.
func process(ch *transport.MsgChannel, from, to *core.Peer) (err error) {
	sig := concurrent.NewSignaller() // signaller instance

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
		}
	}
}
