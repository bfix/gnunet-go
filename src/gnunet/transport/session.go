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

package transport

// Session states
const (
	KxStateDown        = iota // No handshake yet.
	KxStateKeySent            // We've sent our session key.
	KxStateKeyReceived        // We've received the other peers session key.
	KxStateUp                 // Key exchange is done.
	KxStateRekeySent          // We're rekeying (or had a timeout).
	KxPeerDisconnect          // Last state of a KX (when it is being terminated).
)
