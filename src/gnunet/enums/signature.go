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

package enums

// Signature purpose constants
const (
	SIG_TEST                           = 0  // Test signature, not valid for anything other than writing a test.
	SIG_TRANSPORT_PONG_OWN             = 1  // Signature for confirming that this peer uses a particular address.
	SIG_TRANSPORT_DISCONNECT           = 2  // Signature for confirming that this peer intends to disconnect.
	SIG_REVOCATION                     = 3  // Signature for confirming a key revocation.
	SIG_NAMESPACE_ADVERTISEMENT        = 4  // Signature for a namespace/pseudonym advertisement (by the namespace owner).
	SIG_PEER_PLACEMENT                 = 5  // Signature by which a peer affirms that it is providing a certain bit of content for use in LOCation URIs.
	SIG_DHT_HOP                        = 6  // Signature by which a peer affirms that it forwarded a message in the DHT.
	SIG_HELLO                          = 7  // Signature by which a peer affirms its address.
	SIG_DNS_RECORD                     = 11 // Signature on a GNUNET_DNS_Advertisement.
	SIG_CHAT_MESSAGE                   = 12 // Signature of a chat message.
	SIG_CHAT_RECEIPT                   = 13 // Signature of confirmation receipt for a chat message.
	SIG_NSE_SEND                       = 14 // Signature of a network size estimate message.
	SIG_GNS_RECORD_SIGN                = 15 // Signature of a gnunet naming system record block
	SIG_SET_ECC_KEY                    = 16 // Purpose is to set a session key.
	SIG_FS_UBLOCK                      = 17 // UBlock Signature, done using DSS, not ECC
	SIG_REGEX_ACCEPT                   = 18 // Accept state in regex DFA.  Peer affirms that it offers the matching service.
	SIG_CONVERSATION_RING              = 20 // Signature of a conversation ring.
	SIG_SECRETSHARING_DKG1             = 21 // Signature for the first round of distributed key generation.
	SIG_SECRETSHARING_DKG2             = 22 // Signature for the second round of distributed key generation.
	SIG_SECRETSHARING_DECRYPTION       = 23 // Signature for the cooperative decryption.
	SIG_RECLAIM_CODE_SIGN              = 27 // Signature for a GNUid Ticket
	SIG_DELEGATE                       = 28 // Signature for a GNUnet credential
	SIG_TRANSPORT_ADDRESS              = 29 // Signature by a peer affirming that this is one of its addresses for the given time period.
	SIG_TRANSPORT_EPHEMERAL            = 30 // Signature by a peer affirming that the given ephemeral key is currently in use by that peer
	SIG_COMMUNICATOR_TCP_HANDSHAKE     = 31 // Signature used by TCP communicator handshake.
	SIG_COMMUNICATOR_TCP_REKEY         = 32 // Signature used by TCP communicator rekey.
	SIG_COMMUNICATOR_UDP_HANDSHAKE     = 33 // Signature used by UDP communicator handshake.
	SIG_COMMUNICATOR_UDP_BROADCAST     = 34 // Signature used by UDP broadcasts.
	SIG_TRANSPORT_CHALLENGE            = 35 // Signature by a peer affirming that it received a challenge
	SIG_TRANSPORT_DV_HOP               = 36 // Signature by a peer affirming that it is on a DV path.
	SIG_TRANSPORT_DV_INITIATOR         = 37 // Signature by a peer affirming that it originated the DV path.
	SIG_CADET_CONNECTION_INITIATOR     = 38 // Signature by a peer that like to create a connection.
	SIG_COMMUNICATOR_TCP_HANDSHAKE_ACK = 39 // Signature by a peer sending back the nonce received at initial handshake.
)
