package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bfix/gospel/logger"
	"gnunet/config"
	"gnunet/service"
	"gnunet/service/gns"
)

func main() {
	logger.Println(logger.INFO, "[gns] Starting service...")
	var (
		cfgFile  string
		srvEndp  string
		err      error
		logLevel int
	)
	// handle command line arguments
	flag.StringVar(&cfgFile, "c", "gnunet-config.json", "GNUnet configuration file")
	flag.StringVar(&srvEndp, "s", "", "GNS service end-point")
	flag.IntVar(&logLevel, "L", logger.INFO, "GNS log level (default: INFO)")
	flag.Parse()

	// read configuration file and set missing arguments.
	if err = config.ParseConfig(cfgFile); err != nil {
		logger.Printf(logger.ERROR, "[gns] Invalid configuration file: %s\n", err.Error())
		return
	}

	// apply configuration
	logger.SetLogLevel(logLevel)
	if len(srvEndp) == 0 {
		srvEndp = config.Cfg.GNS.Endpoint
	}

	// start a new GNS service
	gns := gns.NewGNSService()
	srv := service.NewServiceImpl("gns", gns)
	if err = srv.Start(srvEndp); err != nil {
		logger.Printf(logger.ERROR, "[gns] Error: '%s'\n", err.Error())
		return
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
				logger.Printf(logger.INFO, "[gns] Terminating service (on signal '%s')\n", sig)
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
	// flush last messages
	logger.Flush()
}
