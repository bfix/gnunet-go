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

package service

import (
	"context"
	"gnunet/config"
	"net/http"
	"time"

	"github.com/bfix/gospel/logger"
	"github.com/gorilla/mux"
)

// JSON-RPC interface for services to be used as the primary client API
// for perform, manage and monitor GNUnet activities.

// Router for JSON-RPC requests
var Router = mux.NewRouter()
var srv *http.Server

// StartRPC the JSON-RPC server. It can be terminated by context
func StartRPC(ctx context.Context) error {
	// instantiate a server and run it
	srv = &http.Server{
		Handler:      Router,
		Addr:         config.Cfg.RPC.Endpoint,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	go func() {
		// start listening
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				logger.Printf(logger.WARN, "[RPC] Server listen failed: %s", err.Error())
			}
		}()
		select {
		case <-ctx.Done():
			if err := srv.Shutdown(context.Background()); err != nil {
				logger.Printf(logger.WARN, "[RPC] Server shutdownn failed: %s", err.Error())
			}
		}
	}()
	return nil
}

// RegisterRPC a JSON-RPC path in a service-specific processor
func RegisterRPC(m Module) {
	path, hdlr := m.RPC()
	Router.HandleFunc(path, hdlr)
}
