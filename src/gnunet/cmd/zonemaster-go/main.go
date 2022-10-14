// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2022 Bernd Fix  >Y<
//
// gnunet-go is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// gnunet-go is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL3.0-or-later

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gnunet/config"
	"gnunet/service"
	"gnunet/service/zonemaster"

	"github.com/bfix/gospel/logger"
)

func main() {
	defer func() {
		logger.Println(logger.INFO, "[zonemaster] Bye.")
		// flush last messages
		logger.Flush()
	}()
	// intro
	logger.SetLogLevel(logger.DBG)
	logger.Println(logger.INFO, "[zonemaster] Starting service...")

	var (
		cfgFile  string
		dhtSock  string
		err      error
		logLevel int
		rpcEndp  string
	)
	// handle command line arguments
	flag.StringVar(&cfgFile, "c", "gnunet-config.json", "GNUnet configuration file")
	flag.StringVar(&dhtSock, "d", "", "DHT service socket")
	flag.IntVar(&logLevel, "L", logger.INFO, "zonemaster log level (default: INFO)")
	flag.StringVar(&rpcEndp, "R", "", "JSON-RPC endpoint (default: none)")
	flag.Parse()

	// read configuration file and set missing arguments.
	if err = config.ParseConfig(cfgFile); err != nil {
		logger.Printf(logger.ERROR, "[zonemaster] Invalid configuration file: %s\n", err.Error())
		return
	}

	// apply configuration
	if config.Cfg.Logging.Level > 0 {
		logLevel = config.Cfg.Logging.Level
	}
	logger.SetLogLevel(logLevel)
	if len(dhtSock) == 0 {
		dhtSock = config.Cfg.DHT.Service.Socket
	}

	// start a new ZONEMASTER service
	ctx, cancel := context.WithCancel(context.Background())
	// TODO: start background service; start HTTPS backend
	zmSrv := zonemaster.NewZoneMaster(dhtSock)

	// handle command-line arguments for RPC
	if len(rpcEndp) > 0 {
		parts := strings.Split(rpcEndp, ":")
		if parts[0] != "tcp" {
			logger.Println(logger.ERROR, "[zonemaster] RPC must have a TCP/IP endpoint")
			return
		}
		config.Cfg.RPC.Endpoint = parts[1]
	}
	// start JSON-RPC server on request
	if ep := config.Cfg.RPC.Endpoint; len(ep) > 0 {
		var rpc *service.JRPCServer
		if rpc, err = service.RunRPCServer(ctx, ep); err != nil {
			logger.Printf(logger.ERROR, "[zonemaster] RPC failed to start: %s", err.Error())
			return
		}
		zmSrv.InitRPC(rpc)
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
				logger.Printf(logger.INFO, "[zonemaster] Terminating service (on signal '%s')\n", sig)
				break loop
			case syscall.SIGHUP:
				logger.Println(logger.INFO, "[zonemaster] SIGHUP")
			case syscall.SIGURG:
				// TODO: https://github.com/golang/go/issues/37942
			default:
				logger.Println(logger.INFO, "[zonemaster] Unhandled signal: "+sig.String())
			}
		// handle heart beat
		case now := <-tick.C:
			logger.Println(logger.INFO, "[zonemaster] Heart beat at "+now.String())
		}
	}

	// terminating service
	cancel()
}
