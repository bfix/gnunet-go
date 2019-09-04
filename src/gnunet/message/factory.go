package message

import (
	"errors"
	"fmt"
)

// NewEmptyMessage creates a new empty message object for the given type.
func NewEmptyMessage(msgType uint16) (Message, error) {
	switch msgType {
	//------------------------------------------------------------------
	// Transport
	//------------------------------------------------------------------
	case TRANSPORT_TCP_WELCOME:
		return NewTransportTcpWelcomeMsg(nil), nil
	case HELLO:
		return NewHelloMsg(nil), nil
	case TRANSPORT_SESSION_QUOTA:
		return NewSessionQuotaMsg(0), nil
	case TRANSPORT_SESSION_SYN:
		return NewSessionSynMsg(0), nil
	case TRANSPORT_SESSION_SYN_ACK:
		return NewSessionSynAckMsg(0), nil
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
	case DHT_CLIENT_GET:
		return NewDHTClientGetMsg(), nil

	//------------------------------------------------------------------
	// GNS
	//------------------------------------------------------------------
	case GNS_LOOKUP:
		return NewGNSLookupMsg(), nil
	case GNS_LOOKUP_RESULT:
		return NewGNSLookupResultMsg(), nil

	//------------------------------------------------------------------
	// Namecache
	//------------------------------------------------------------------
	case NAMECACHE_LOOKUP_BLOCK:
		return NewNamecacheLookupMsg(nil), nil
	case NAMECACHE_LOOKUP_BLOCK_RESPONSE:
		return NewNamecacheLookupResultMsg(), nil
	}
	return nil, errors.New(fmt.Sprintf("Unknown message type %d", msgType))
}
