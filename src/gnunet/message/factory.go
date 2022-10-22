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
	"gnunet/enums"
)

// NewEmptyMessage creates a new empty message object for the given type.
//
//nolint:gocyclo // it's a long switch intentionally
func NewEmptyMessage(msgType enums.MsgType) (Message, error) {
	switch msgType {
	//------------------------------------------------------------------
	// Transport
	//------------------------------------------------------------------
	case enums.MSG_TRANSPORT_TCP_WELCOME:
		return NewTransportTCPWelcomeMsg(nil), nil
	case enums.MSG_HELLO:
		return NewHelloMsg(nil), nil
	case enums.MSG_TRANSPORT_SESSION_QUOTA:
		return NewSessionQuotaMsg(0), nil
	case enums.MSG_TRANSPORT_SESSION_SYN:
		return NewSessionSynMsg(), nil
	case enums.MSG_TRANSPORT_SESSION_SYN_ACK:
		return NewSessionSynAckMsg(), nil
	case enums.MSG_TRANSPORT_SESSION_ACK:
		return new(SessionAckMsg), nil
	case enums.MSG_TRANSPORT_PING:
		return NewTransportPingMsg(nil, nil), nil
	case enums.MSG_TRANSPORT_PONG:
		return NewTransportPongMsg(0, nil), nil
	case enums.MSG_TRANSPORT_SESSION_KEEPALIVE:
		return NewSessionKeepAliveMsg(), nil

	//------------------------------------------------------------------
	// Core
	//------------------------------------------------------------------
	case enums.MSG_CORE_EPHEMERAL_KEY:
		return NewEphemeralKeyMsg(), nil

	//------------------------------------------------------------------
	// DHT
	//------------------------------------------------------------------
	case enums.MSG_DHT_CLIENT_PUT:
		return NewDHTClientPutMsg(nil, 0, nil), nil
	case enums.MSG_DHT_CLIENT_GET:
		return NewDHTClientGetMsg(nil), nil
	case enums.MSG_DHT_CLIENT_GET_STOP:
		return NewDHTClientGetStopMsg(nil), nil
	case enums.MSG_DHT_CLIENT_RESULT:
		return NewDHTClientResultMsg(nil), nil
	case enums.MSG_DHT_CLIENT_GET_RESULTS_KNOWN:
		return NewDHTClientGetResultsKnownMsg(nil), nil

	//------------------------------------------------------------------
	// DHT-P2P
	//------------------------------------------------------------------
	case enums.MSG_DHT_P2P_HELLO:
		return NewDHTP2PHelloMsg(), nil
	case enums.MSG_DHT_P2P_GET:
		return NewDHTP2PGetMsg(), nil
	case enums.MSG_DHT_P2P_PUT:
		return NewDHTP2PPutMsg(nil), nil
	case enums.MSG_DHT_P2P_RESULT:
		return NewDHTP2PResultMsg(), nil

	//------------------------------------------------------------------
	// GNS
	//------------------------------------------------------------------
	case enums.MSG_GNS_LOOKUP:
		return NewGNSLookupMsg(), nil
	case enums.MSG_GNS_LOOKUP_RESULT:
		return NewGNSLookupResultMsg(0), nil

	//------------------------------------------------------------------
	// Namecache
	//------------------------------------------------------------------
	case enums.MSG_NAMECACHE_LOOKUP_BLOCK:
		return NewNamecacheLookupMsg(nil), nil
	case enums.MSG_NAMECACHE_LOOKUP_BLOCK_RESPONSE:
		return NewNamecacheLookupResultMsg(), nil
	case enums.MSG_NAMECACHE_BLOCK_CACHE:
		return NewNamecacheCacheMsg(nil), nil
	case enums.MSG_NAMECACHE_BLOCK_CACHE_RESPONSE:
		return NewNamecacheCacheResponseMsg(), nil

	//------------------------------------------------------------------
	// Revocation
	//------------------------------------------------------------------
	case enums.MSG_REVOCATION_QUERY:
		return NewRevocationQueryMsg(nil), nil
	case enums.MSG_REVOCATION_QUERY_RESPONSE:
		return NewRevocationQueryResponseMsg(true), nil
	case enums.MSG_REVOCATION_REVOKE:
		return NewRevocationRevokeMsg(nil), nil
	case enums.MSG_REVOCATION_REVOKE_RESPONSE:
		return NewRevocationRevokeResponseMsg(false), nil

	//------------------------------------------------------------------
	// Namestore service
	//------------------------------------------------------------------
	case enums.MSG_NAMESTORE_ZONE_ITERATION_START:
		return NewNamestoreZoneIterStartMsg(nil), nil
	case enums.MSG_NAMESTORE_ZONE_ITERATION_NEXT:
	case enums.MSG_NAMESTORE_ZONE_ITERATION_STOP:
	case enums.MSG_NAMESTORE_RECORD_STORE:
	case enums.MSG_NAMESTORE_RECORD_STORE_RESPONSE:
	case enums.MSG_NAMESTORE_RECORD_LOOKUP:
	case enums.MSG_NAMESTORE_RECORD_LOOKUP_RESPONSE:
	case enums.MSG_NAMESTORE_ZONE_TO_NAME:
	case enums.MSG_NAMESTORE_ZONE_TO_NAME_RESPONSE:
	case enums.MSG_NAMESTORE_MONITOR_START:
	case enums.MSG_NAMESTORE_MONITOR_SYNC:
	case enums.MSG_NAMESTORE_RECORD_RESULT:
	case enums.MSG_NAMESTORE_MONITOR_NEXT:
	}
	return nil, fmt.Errorf("unknown message type %d", msgType)
}
