package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gnunet/service"
	"gnunet/service/gns"
)

func main() {
	var (
		srvEndp string
	)
	// handle command line arguments
	flag.StringVar(&srvEndp, "s", "unix+/tmp/gnunet-service-gns-go.sock", "GNS service end-point")
	flag.Parse()

	// start a new GNS service
	gns := gns.NewGNSService()
	srv := service.NewServiceImpl(gns)
	if err := srv.Start(srvEndp); err != nil {
		log.Fatal(err)
	}
	defer srv.Stop()

	// handle OS signals
	sigCh := make(chan os.Signal, 5)
	signal.Notify(sigCh)

	// heart beat
	tick := time.NewTicker(5 * time.Minute)

	for {
		select {
		// handle OS signals
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGKILL:
			case syscall.SIGINT:
			case syscall.SIGTERM:
				log.Println("[gns] Terminating service (on signal)")
				break
			case syscall.SIGHUP:
				log.Println("[gns] SIGHUP")
			default:
				log.Println("[gns] Unhandled signal: " + sig.String())
			}
		// handle heart beat
		case now := <-tick.C:
			log.Println("[gns] Heart beat at " + now.String())
		}
	}
}
