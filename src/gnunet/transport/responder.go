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
	"context"
	"errors"
	"gnunet/message"
	"gnunet/util"
)

//----------------------------------------------------------------------
// Responder is a back-channel for messages generated during
// message processing. The Connection type is a responder
// and used as such in ServeClient().
type Responder interface {
	// Handle outgoing message
	Send(ctx context.Context, msg message.Message) error

	// Receiver returns the receiving peer. Returns nil if
	// this is a local responder (service.Connection)
	Receiver() *util.PeerID
}

//----------------------------------------------------------------------
// TransportResponder is used as a responder in message handling for
// messages received from Transport. It is used by Endpoint instances
// to define custom responders for messages received.
type TransportResponder struct {
	Peer    *util.PeerID
	SendFcn func(context.Context, *util.PeerID, message.Message) error
}

// Send a message back to caller. The specifics are handled in the callback.
func (r *TransportResponder) Send(ctx context.Context, msg message.Message) error {
	if r.SendFcn == nil {
		return errors.New("no send function defined")
	}
	return r.SendFcn(ctx, r.Peer, msg)
}

// Receiver returns the receiving peer id
func (r *TransportResponder) Receiver() *util.PeerID {
	return r.Peer
}
