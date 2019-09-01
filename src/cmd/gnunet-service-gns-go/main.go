package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bfix/gospel/logger"
	"gnunet/service"
	"gnunet/service/gns"
)

func main() {
	var (
		srvEndp string
	)
	// handle command line arguments
	flag.StringVar(&srvEndp, "s", "unix+/tmp/gnunet-system-runtime/gnunet-service-gns-go.sock", "GNS service end-point")
	flag.Parse()

	logger.SetLogLevel(logger.DBG)

	// start a new GNS service
	gns := gns.NewGNSService()
	srv := service.NewServiceImpl("gns", gns)
	if err := srv.Start(srvEndp); err != nil {
		logger.Printf(logger.ERROR, "[gns] Error: '%s'\n", err.Error())
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
			case syscall.SIGKILL:
			case syscall.SIGINT:
			case syscall.SIGTERM:
				logger.Println(logger.INFO, "[gns] Terminating service (on signal)")
				break loop
			case syscall.SIGHUP:
				logger.Println(logger.INFO, "[gns] SIGHUP")
			default:
				logger.Println(logger.INFO, "[gns] Unhandled signal: "+sig.String())
			}
		// handle heart beat
		case now := <-tick.C:
			logger.Println(logger.INFO, "[gns] Heart beat at "+now.String())
		}
	}

	// terminating service
	srv.Stop()
	// wait for logger to flush last messages
	time.Sleep(5 * time.Second)
}
