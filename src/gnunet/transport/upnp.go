// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2022 Bernd Fix  >Y<
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

package transport

import (
	"errors"
	"strings"

	"github.com/bfix/gospel/network"
)

//----------------------------------------------------------------------
// Package local reference to PortMapper instance

var (
	upnpManager *network.PortMapper
)

// initialize at start-up
func init() {
	upnpManager, _ = network.NewPortMapper("gnunet-go")
}

//----------------------------------------------------------------------
// UPNP returns a local address for listening that will receive traffic
// from a port forward handled by UPnP on the router.
func UPNP(protocol, addr string, port int) (id, local, remote string, err error) {
	// check address format.
	if !strings.HasPrefix(addr, "upnp:") {
		err = errors.New("invalid address for UPNP")
		return
	}
	return upnpManager.Assign(protocol, port)
}
