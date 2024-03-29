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
	"time"
)

// Time constants
var (
	// How long is a PONG signature valid?  We'll recycle a signature until
	// 1/4 of this time is remaining.  PONGs should expire so that if our
	// external addresses change an adversary cannot replay them indefinitely.
	// OTOH, we don't want to spend too much time generating PONG signatures,
	// so they must have some lifetime to reduce our CPU usage.
	PongSignatureLifetime = 1 * time.Hour

	// After how long do we expire an address in a HELLO that we just
	// validated?  This value is also used for our own addresses when we
	// create a HELLO.
	HelloAddressExpiration = 12 * time.Hour

	// How often do we allow PINGing an address that we have not yet
	// validated?  This also determines how long we track an address that
	// we cannot validate (because after this time we can destroy the
	// validation record).
	UnvalidatedPingKeepAlive = 5 * time.Minute

	// How often do we PING an address that we have successfully validated
	// in the past but are not actively using?  Should be (significantly)
	// smaller than HELLO_ADDRESS_EXPIRATION.
	ValidatedPingFrequency = 15 * time.Minute

	// How often do we PING an address that we are currently using?
	ConnectedPingFrequency = 2 * time.Minute

	// How much delay is acceptable for sending the PING or PONG?
	AcceptablePingDelay = 1 * time.Second
)
