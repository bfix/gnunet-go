package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gnunet/service/revocation"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
)

func main() {
	fmt.Println("=================================")
	fmt.Println("Compute revocation data block")
	fmt.Println("for a random zone key (test mode)")
	fmt.Println("Press ^C to abort...")
	fmt.Println("=================================")

	var (
		quiet bool
		bits  int
	)
	flag.IntVar(&bits, "b", 20, "Number of leading zero bits")
	flag.BoolVar(&quiet, "q", false, "Be quiet")
	flag.Parse()

	// pre-set difficulty
	fmt.Printf("Leading zeros required: %d\n", bits)

	// generate a random key pair
	pkey, skey := ed25519.NewKeypair()

	// set expiration time
	ts := util.AbsoluteTimeNow()
	ttl := util.NewRelativeTime(2 * 365 * 24 * time.Hour)

	// initialize RevData structure
	rd := revocation.NewRevData(ts, ttl, pkey)
	if err := rd.Sign(skey); err != nil {
		log.Fatal(err)
	}

	ctx, cancelFcn := context.WithCancel(context.Background())
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if result := rd.Compute(ctx, bits); result != 32 {
			fmt.Printf("Incomplete revocation: Only %d of 32 PoWs available!\n", result)
		} else {
			fmt.Printf("REVDATA = %s\n", hex.EncodeToString(rd.Blob()))
		}
	}()

	go func() {
		// handle OS signals
		sigCh := make(chan os.Signal, 5)
		signal.Notify(sigCh)
	loop:
		for {
			select {
			// handle OS signals
			case sig := <-sigCh:
				switch sig {
				case syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM:
					log.Printf("Terminating (on signal '%s')\n", sig)
					cancelFcn()
					break loop
				case syscall.SIGHUP:
					log.Println("SIGHUP")
				case syscall.SIGURG:
					// TODO: https://github.com/golang/go/issues/37942
				default:
					log.Println("Unhandled signal: " + sig.String())
				}
			}
		}
	}()

	wg.Wait()
	log.Printf("Verify: %d\n", rd.Verify())
}
