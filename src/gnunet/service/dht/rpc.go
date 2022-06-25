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
)

//----------------------------------------------------------------------

// DHTService is a type for DHT-related JSON-RPC requests
type DHTService struct{}

// local instance of service
var dhtRPC = &DHTService{}

//----------------------------------------------------------------------
// Command "DHT.Status"
//----------------------------------------------------------------------

// DHTStatusRequest is a status request for specific information addressed
// by name(s)
type DHTStatusRequest struct {
	Topics []string `json:"topics"`
}

type DHTStatusResponse struct {
	Messages map[string]string `json:"messages"`
}

func (s *DHTService) Status(r *http.Request, req *DHTStatusRequest, reply *DHTStatusResponse) error {
	out := make(map[string]string)
	for _, topic := range req.Topics {
		switch topic {
		case "echo":
			out[topic] = "echo test"
		}
	}
	*reply = DHTStatusResponse{
		Messages: out,
	}
	return nil
}

//----------------------------------------------------------------------

// InitRPC registers RPC commands for the module
func (m *Module) InitRPC(srv *service.JRPCServer) {
	srv.RegisterService(dhtRPC, "DHT")
}
