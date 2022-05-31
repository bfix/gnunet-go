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
	"gnunet/util"
	"net"
)

//----------------------------------------------------------------------
// UDP endpoint
//----------------------------------------------------------------------

type UDPEndpoint struct {
	addr   *net.UDPAddr
	listen *net.UDPConn
	ch     chan *TransportMessage
}

func (ep *UDPEndpoint) Run(ch chan *TransportMessage) error {
	return nil
}

func (ep *UDPEndpoint) Send(msg *TransportMessage) error {
	return nil
}

func (ep *UDPEndpoint) Address() *util.Address {
	return nil
}

func NewUDPEndpoint(addr *util.Address) (*UDPEndpoint, error) {
	return nil, nil
}

//----------------------------------------------------------------------
// TCP endpoint
//----------------------------------------------------------------------

type TCPEndpoint struct {
	addr   *net.TCPAddr
	listen *net.TCPListener
	ch     chan *TransportMessage
}

func (ep *TCPEndpoint) Run(ch chan *TransportMessage) error {
	return nil
}

func (ep *TCPEndpoint) Send(msg *TransportMessage) error {
	return nil
}

func (ep *TCPEndpoint) Address() *util.Address {
	return nil
}

func NewTCPEndpoint(addr *util.Address) (*UDPEndpoint, error) {
	return nil, nil
}

//----------------------------------------------------------------------
// UDS (Unix domain socket) endpoint
//----------------------------------------------------------------------

type UDSEndpoint struct {
	addr   string
	listen *net.UnixConn
	ch     chan *TransportMessage
}

func (ep *UDSEndpoint) Run(ch chan *TransportMessage) error {
	return nil
}

func (ep *UDSEndpoint) Send(msg *TransportMessage) error {
	return nil
}

func (ep *UDSEndpoint) Address() *util.Address {
	return nil
}

func NewUDSEndpoint(addr *util.Address) (*UDPEndpoint, error) {
	return nil, nil
}
