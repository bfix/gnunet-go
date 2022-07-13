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

package dht

import (
	"gnunet/service"
	"net/http"

	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------

// RPCService is a type for DHT-related JSON-RPC requests
type RPCService struct{}

// local instance of service
var dhtRPC = &RPCService{}

//----------------------------------------------------------------------
// Command "DHT.Status"
//----------------------------------------------------------------------

// StatusRequest is a status request for specific information addressed
// by topic(s)
type StatusRequest struct {
	Topics []string `json:"topics"`
}

// StatusResponse is a response to a status request. It returns information
// on each topic requested.
type StatusResponse struct {
	Messages map[string]string `json:"messages"`
}

// Status requests information by topic(s).
func (s *RPCService) Status(r *http.Request, req *StatusRequest, reply *StatusResponse) error {
	// assemble information on topic(s)
	out := make(map[string]string)
	for _, topic := range req.Topics {
		switch topic {
		case "echo":
			out[topic] = "echo test"
		}
	}
	// set reply
	*reply = StatusResponse{
		Messages: out,
	}
	return nil
}

//----------------------------------------------------------------------

// InitRPC registers RPC commands for the module
func (m *Module) InitRPC(srv *service.JRPCServer) {
	if err := srv.RegisterService(dhtRPC, "DHT"); err != nil {
		logger.Printf(logger.ERROR, "[dht] Failed to init RPC: %s", err.Error())
	}
}
