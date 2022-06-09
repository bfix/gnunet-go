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

package message

import (
	"fmt"
)

// NewEmptyMessage creates a new empty message object for the given type.
func NewEmptyMessage(msgType uint16) (Message, error) {
	switch msgType {
	//------------------------------------------------------------------
	// Transport
	//------------------------------------------------------------------
	case TRANSPORT_TCP_WELCOME:
		return NewTransportTCPWelcomeMsg(nil), nil
	case HELLO:
		return NewHelloMsg(nil), nil
	case TRANSPORT_SESSION_QUOTA:
		return NewSessionQuotaMsg(0), nil
	case TRANSPORT_SESSION_SYN:
		return NewSessionSynMsg(), nil
	case TRANSPORT_SESSION_SYN_ACK:
		return NewSessionSynAckMsg(), nil
	case TRANSPORT_SESSION_ACK:
		return new(SessionAckMsg), nil
	case TRANSPORT_PING:
		return NewTransportPingMsg(nil, nil), nil
	case TRANSPORT_PONG:
		return NewTransportPongMsg(0, nil), nil
	case TRANSPORT_SESSION_KEEPALIVE:
		return NewSessionKeepAliveMsg(), nil

	//------------------------------------------------------------------
	// Core
	//------------------------------------------------------------------
	case CORE_EPHEMERAL_KEY:
		return NewEphemeralKeyMsg(), nil

	//------------------------------------------------------------------
	// DHT
	//------------------------------------------------------------------
	case DHT_CLIENT_PUT:
		return NewDHTClientPutMsg(nil, 0, nil), nil
	case DHT_CLIENT_GET:
		return NewDHTClientGetMsg(nil), nil
	case DHT_CLIENT_GET_STOP:
		return NewDHTClientGetStopMsg(nil), nil
	case DHT_CLIENT_RESULT:
		return NewDHTClientResultMsg(nil), nil
	case DHT_CLIENT_GET_RESULTS_KNOWN:
		return NewDHTClientGetResultsKnownMsg(nil), nil

	//------------------------------------------------------------------
	// GNS
	//------------------------------------------------------------------
	case GNS_LOOKUP:
		return NewGNSLookupMsg(), nil
	case GNS_LOOKUP_RESULT:
		return NewGNSLookupResultMsg(0), nil

	//------------------------------------------------------------------
	// Namecache
	//------------------------------------------------------------------
	case NAMECACHE_LOOKUP_BLOCK:
		return NewNamecacheLookupMsg(nil), nil
	case NAMECACHE_LOOKUP_BLOCK_RESPONSE:
		return NewNamecacheLookupResultMsg(), nil
	case NAMECACHE_BLOCK_CACHE:
		return NewNamecacheCacheMsg(nil), nil
	case NAMECACHE_BLOCK_CACHE_RESPONSE:
		return NewNamecacheCacheResponseMsg(), nil

	//------------------------------------------------------------------
	// Revocation
	//------------------------------------------------------------------
	case REVOCATION_QUERY:
		return NewRevocationQueryMsg(nil), nil
	case REVOCATION_QUERY_RESPONSE:
		return NewRevocationQueryResponseMsg(true), nil
	case REVOCATION_REVOKE:
		return NewRevocationRevokeMsg(nil), nil
	case REVOCATION_REVOKE_RESPONSE:
		return NewRevocationRevokeResponseMsg(false), nil
	}
	return nil, fmt.Errorf("unknown message type %d", msgType)
}
