package main

import (
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/bfix/gospel/logger"
	"gnunet/core"
	"gnunet/transport"
)

var (
	p *core.Peer // local peer (with private key)
	t *core.Peer // remote peer
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
	fmt.Printf("    Identity '%s'\n", p.GetIDString())
	fmt.Printf("    [%s]\n", hex.EncodeToString(p.GetID()))
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
					if err = process(mc, t, p); err != nil {
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
		err = process(mc, p, t)
	}
	if err != nil {
		fmt.Println(err)
	}
}
