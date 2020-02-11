// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
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
	"gnunet/message"
	"gnunet/transport"

	"github.com/bfix/gospel/logger"
)

// Client
type Client struct {
	ch *transport.MsgChannel
}

// NewClient
func NewClient(endp string) (*Client, error) {
	//
	ch, err := transport.NewChannel(endp)
	if err != nil {
		return nil, err
	}
	return &Client{
		ch: transport.NewMsgChannel(ch),
	}, nil
}

func (c *Client) SendRequest(req message.Message) error {
	return c.ch.Send(req)
}

func (c *Client) ReceiveResponse() (message.Message, error) {
	return c.ch.Receive()
}

func (c *Client) Close() error {
	return c.ch.Close()
}

func ServiceRequestResponse(caller, callee, endp string, req message.Message) (message.Message, error) {
	// client-connect to the service
	logger.Printf(logger.DBG, "[%s] Connect to %s service\n", caller, callee)
	cl, err := NewClient(endp)
	if err != nil {
		return nil, err
	}
	// send request
	logger.Printf(logger.DBG, "[%s] Sending request to %s service\n", caller, callee)
	if err = cl.SendRequest(req); err != nil {
		return nil, err
	}
	// wait for a single response, then close the connection
	logger.Printf(logger.DBG, "[%s] Waiting for response from %s service\n", caller, callee)
	var resp message.Message
	if resp, err = cl.ReceiveResponse(); err != nil {
		return nil, err
	}
	logger.Printf(logger.DBG, "[%s] Closing connection to %s service\n", caller, callee)
	cl.Close()
	return resp, nil
}
