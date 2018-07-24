package message

import (
	"time"
)

// Time constants
var (
	// How long is a PONG signature valid?  We'll recycle a signature until
	// 1/4 of this time is remaining.  PONGs should expire so that if our
	// external addresses change an adversary cannot replay them indefinitely.
	// OTOH, we don't want to spend too much time generating PONG signatures,
	// so they must have some lifetime to reduce our CPU usage.
	PONG_SIGNATURE_LIFETIME = 1 * time.Hour

	// After how long do we expire an address in a HELLO that we just
	// validated?  This value is also used for our own addresses when we
	// create a HELLO.
	HELLO_ADDRESS_EXPIRATION = 12 * time.Hour

	// How often do we allow PINGing an address that we have not yet
	// validated?  This also determines how long we track an address that
	// we cannot validate (because after this time we can destroy the
	// validation record).
	UNVALIDATED_PING_KEEPALIVE = 5 * time.Minute

	// How often do we PING an address that we have successfully validated
	// in the past but are not actively using?  Should be (significantly)
	// smaller than HELLO_ADDRESS_EXPIRATION.
	VALIDATED_PING_FREQUENCY = 15 * time.Minute

	// How often do we PING an address that we are currently using?
	CONNECTED_PING_FREQUENCY = 2 * time.Minute

	// How much delay is acceptable for sending the PING or PONG?
	ACCEPTABLE_PING_DELAY = 1 * time.Second
)
