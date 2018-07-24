package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"

	"gnunet/core"
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
		srv      net.Listener
		conn     net.Conn
	)
	flag.BoolVar(&asServer, "s", false, "accept incoming connections")
	flag.Parse()

	// setup peer instances from static data
	if err = setupPeers(false); err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("======================================================================")
	fmt.Println("GNUnet peer mock-up (EXPERIMENTAL)          (c) 2018 by Bernd Fix, >Y<")
	fmt.Printf("    Identity '%s'\n", p.GetIDString())
	fmt.Printf("    [%s]\n", hex.EncodeToString(p.GetID()))
	fmt.Println("======================================================================")

	if asServer {
		// run as server (accepting ONE incoming connection)
		fmt.Println("Waiting for connections...")
		if srv, err = net.Listen("tcp", "0.0.0.0:2086"); err == nil {
			defer srv.Close()
			if conn, err = srv.Accept(); err == nil {
				err = process(conn, t, p)
			}
		}
	} else {
		// connect to peer
		fmt.Println("Connecting to target peer")
		if conn, err = net.Dial("tcp", "172.17.0.5:2086"); err == nil {
			err = process(conn, p, t)
		}
	}
	if err != nil {
		fmt.Println(err)
	}
}
