package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gnunet/config"
	"gnunet/core"
	"gnunet/crypto"
	"gnunet/message"
	"gnunet/service"

	"github.com/bfix/gospel/logger"
)

var (
	// configuration for local node
	localCfg = &config.NodeConfig{
		PrivateSeed: "YGoe6XFH3XdvFRl+agx9gIzPTvxA229WFdkazEMdcOs=",
		Endpoints: []string{
			"udp:127.0.0.1:2086",
		},
	}
	// configuration for remote node
	remoteCfg  = "3GXXMNb5YpIUO7ejIR2Yy0Cf5texuLfDjHkXcqbPxkc="
	remoteAddr = "udp:172.17.0.5:2086"

	// top-level variables used accross functions
	local  *core.Peer // local peer (with private key)
	remote *core.Peer // remote peer
	c      *core.Core
	secret *crypto.HashCode
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// handle command line arguments
	var (
		asServer bool
		err      error
	)
	flag.BoolVar(&asServer, "s", false, "wait for incoming connections")
	flag.Parse()

	// setup peer and core instances
	if local, err = core.NewLocalPeer(localCfg); err != nil {
		fmt.Println("local failed: " + err.Error())
		return
	}
	if c, err = core.NewCore(ctx, local); err != nil {
		fmt.Println("core failed: " + err.Error())
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

	// handle messages coming from network
	module := service.NewModuleImpl()
	listener := module.Run(c.Context(), process, nil)
	c.Register("mockup", listener)

	if !asServer {
		// we start the message exchange
		c.Send(remote.GetID(), message.NewTransportTCPWelcomeMsg(c.PeerID()))
	}

	// handle OS signals
	sigCh := make(chan os.Signal, 5)
	signal.Notify(sigCh)

	// heart beat
	tick := time.NewTicker(5 * time.Minute)

loop:
	for {
		select {
		// handle OS signals
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM:
				logger.Printf(logger.INFO, "Terminating service (on signal '%s')\n", sig)
				break loop
			case syscall.SIGHUP:
				logger.Println(logger.INFO, "SIGHUP")
			case syscall.SIGURG:
				// TODO: https://github.com/golang/go/issues/37942
			default:
				logger.Println(logger.INFO, "Unhandled signal: "+sig.String())
			}
		// handle heart beat
		case now := <-tick.C:
			logger.Println(logger.INFO, "Heart beat at "+now.String())
		}
	}
	// terminate pending routines
	cancel()
}

// process incoming messages and send responses; it is used for protocol exploration only.
// it tries to mimick the message flow between "real" GNUnet peers.
func process(ctx context.Context, ev *core.Event) {

	logger.Printf(logger.DBG, "<<< %s", ev.Msg.String())

	switch msg := ev.Msg.(type) {

	case *message.TransportTCPWelcomeMsg:
		c.Send(ev.Peer, message.NewTransportPingMsg(ev.Peer, nil))

	case *message.HelloMsg:

	case *message.TransportPingMsg:
		mOut := message.NewTransportPongMsg(msg.Challenge, nil)
		if err := mOut.Sign(local.PrvKey()); err != nil {
			logger.Println(logger.ERROR, "PONG: signing failed")
			return
		}
		c.Send(ev.Peer, mOut)
		logger.Printf(logger.DBG, ">>> %s", mOut)

	case *message.TransportPongMsg:
		rc, err := msg.Verify(remote.PubKey())
		if err != nil {
			logger.Println(logger.ERROR, "PONG verification: "+err.Error())
		}
		if !rc {
			logger.Println(logger.ERROR, "PONG verification failed")
		}

	case *message.SessionSynMsg:
		mOut := message.NewSessionSynAckMsg()
		mOut.Timestamp = msg.Timestamp
		c.Send(ev.Peer, mOut)
		logger.Printf(logger.DBG, ">>> %s", mOut)

	case *message.SessionQuotaMsg:

	case *message.SessionAckMsg:

	case *message.SessionKeepAliveMsg:
		mOut := message.NewSessionKeepAliveRespMsg(msg.Nonce)
		c.Send(ev.Peer, mOut)
		logger.Printf(logger.DBG, ">>> %s", mOut)

	case *message.EphemeralKeyMsg:
		rc, err := msg.Verify(remote.PubKey())
		if err != nil {
			logger.Println(logger.ERROR, "EPHKEY verification: "+err.Error())
			return
		} else if !rc {
			logger.Println(logger.ERROR, "EPHKEY verification failed")
			return
		}
		remote.SetEphKeyMsg(msg)
		mOut := local.EphKeyMsg()
		c.Send(ev.Peer, mOut)
		logger.Printf(logger.DBG, ">>> %s", mOut)
		secret = crypto.SharedSecret(local.EphPrvKey(), remote.EphKeyMsg().Public())

	default:
		fmt.Printf("!!! %v\n", msg)
	}
}
