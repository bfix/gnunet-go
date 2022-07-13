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

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
)

var (
	// configuration for local node
	localCfg = &config.NodeConfig{
		PrivateSeed: "YGoe6XFH3XdvFRl+agx9gIzPTvxA229WFdkazEMdcOs=",
		Endpoints: []*config.EndpointConfig{
			{
				ID:      "local",
				Network: "udp",
				Address: "127.0.0.1",
				Port:    2086,
				TTL:     86400,
			},
		},
	}
	// configuration for remote node
	remoteCfg = "3GXXMNb5YpIUO7ejIR2Yy0Cf5texuLfDjHkXcqbPxkc="

	// top-level variables used across functions
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
	if c, err = core.NewCore(ctx, localCfg); err != nil {
		fmt.Println("core failed: " + err.Error())
		return
	}
	local = c.Peer()
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
	listener := module.Run(ctx, process, nil, 0, nil)
	c.Register("mockup", listener)

	if !asServer {
		// we start the message exchange
		if err := c.Send(ctx, remote.GetID(), message.NewTransportTCPWelcomeMsg(c.PeerID())); err != nil {
			fmt.Printf("send message failed: %s", err.Error())
		}
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
		if err := c.Send(ctx, ev.Peer, message.NewTransportPingMsg(ev.Peer, nil)); err != nil {
			logger.Printf(logger.ERROR, "TransportTCPWelcomeMsg send failed: %s", err.Error())
			return
		}

	case *message.HelloMsg:

	case *message.TransportPingMsg:
		mOut := message.NewTransportPongMsg(msg.Challenge, nil)
		if err := mOut.Sign(local.PrvKey()); err != nil {
			logger.Printf(logger.ERROR, "PONG signing failed: %s", err.Error())
			return
		}
		if err := c.Send(ctx, ev.Peer, mOut); err != nil {
			logger.Printf(logger.ERROR, "TransportPongMsg send failed: %s", err.Error())
			return
		}
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
		if err := c.Send(ctx, ev.Peer, mOut); err != nil {
			logger.Printf(logger.ERROR, "SessionSynAckMsg send failed: %s", err.Error())
		}
		logger.Printf(logger.DBG, ">>> %s", mOut)

	case *message.SessionQuotaMsg:

	case *message.SessionAckMsg:

	case *message.SessionKeepAliveMsg:
		mOut := message.NewSessionKeepAliveRespMsg(msg.Nonce)
		if err := c.Send(ctx, ev.Peer, mOut); err != nil {
			logger.Printf(logger.ERROR, "SessionKeepAliveRespMsg send failed: %s", err.Error())
		}
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
		if err := c.Send(ctx, ev.Peer, mOut); err != nil {
			logger.Printf(logger.ERROR, "EphKeyMsg send failed: %s", err.Error())
		}
		logger.Printf(logger.DBG, ">>> %s", mOut)
		pk := ed25519.NewPublicKeyFromBytes(remote.EphKeyMsg().Public().Data)
		secret = crypto.SharedSecret(local.EphPrvKey(), pk)
		fmt.Printf("Shared secret: %s\n", secret.String())

	default:
		fmt.Printf("!!! %v\n", msg)
	}
}
