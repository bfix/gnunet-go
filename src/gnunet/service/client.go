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
	"context"
	"gnunet/message"

	"github.com/bfix/gospel/logger"
)

// Client type: Use to perform client-side interactions with GNUnet services.
type Client struct {
	ch *Connection // channel for message exchange
}

// NewClient connects to a socket with given path
func NewClient(ctx context.Context, path string) (*Client, error) {
	// create a connection
	ch, err := NewConnection(ctx, path)
	if err != nil {
		return nil, err
	}
	// wrap into a message channel for the client.
	return &Client{
		ch: ch,
	}, nil
}

// SendRequest sends a give message to the service.
func (c *Client) SendRequest(ctx *SessionContext, req message.Message) error {
	return c.ch.Send(ctx.ctx, req)
}

// ReceiveResponse waits for a response from the service; it can be interrupted
// by sending "false" to the cmd channel.
func (c *Client) ReceiveResponse(ctx *SessionContext) (message.Message, error) {
	return c.ch.Receive(ctx.ctx)
}

// Close a client; no further message exchange is possible.
func (c *Client) Close() error {
	return c.ch.Close()
}

// RequestResponse is a helper method for a one request - one response
// secenarios of client/serice interactions.
func RequestResponse(
	ctx *SessionContext,
	caller string,
	callee string,
	path string,
	req message.Message) (message.Message, error) {

	// client-connect to the service
	logger.Printf(logger.DBG, "[%s] Connecting to %s service...\n", caller, callee)
	cl, err := NewClient(ctx.ctx, path)
	if err != nil {
		return nil, err
	}
	// send request
	logger.Printf(logger.DBG, "[%s] Sending request to %s service\n", caller, callee)
	if err = cl.SendRequest(ctx, req); err != nil {
		return nil, err
	}
	// wait for a single response, then close the connection
	logger.Printf(logger.DBG, "[%s] Waiting for response from %s service\n", caller, callee)
	var resp message.Message
	if resp, err = cl.ReceiveResponse(ctx); err != nil {
		return nil, err
	}
	logger.Printf(logger.DBG, "[%s] Closing connection to %s service\n", caller, callee)
	cl.Close()
	return resp, nil
}
