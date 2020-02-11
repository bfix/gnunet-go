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

package enums

// Signature purpose constants
const (
	SIG_TEST                     = iota // Only used in test cases!
	SIG_TRANSPORT_PONG_OWN              // Confirming a particular address.
	SIG_TRANSPORT_DISCONNECT            // Confirming intent to disconnect.
	SIG_REVOCATION                      // Confirming a key revocation.
	SIG_NAMESPACE_ADVERTISEMENT         // Namespace/pseudonym advertisement.
	SIG_PEER_PLACEMENT                  // Affirm certain content (LOCation URIs).
	SIG_FS_KBLOCK                       // Obsolete, legacy value.
	SIG_FS_SBLOCK                       // Obsolete, legacy value.
	SIG_FS_NBLOCK                       // Obsolete, legacy value.
	SIG_FS_NBLOCK_KSIG                  // Obsolete, legacy value.
	SIG_RESOLVER_RESPONSE               // DNS_Advertisement
	SIG_DNS_RECORD                      //
	SIG_CHAT_MESSAGE                    // Chat message.
	SIG_CHAT_RECEIPT                    // Confirmation receipt for chat message.
	SIG_NSE_SEND                        // Network size estimate message.
	SIG_GNS_RECORD_SIGN                 // GNS record block.
	SIG_ECC_KEY                         // Set a session key.
	SIG_FS_UBLOCK                       // UBlock Signature, done using DSS, not ECC.
	SIG_REGEX_ACCEPT                    // Accept state (affirm matching service).
	SIG_MULTICAST_MESSAGE               // Multicast message sent by origin.
	SIG_CONVERSATION_RING               // Conversation ring.
	SIG_SECRETSHARING_DKG1              // First round of distributed key generation.
	SIG_SECRETSHARING_DKG2              // Second round of distributed key generation.
	SIG_SECRETSHARING_DECRYPTION        // Cooperative decryption.
	SIG_MULTICAST_REQUEST               // Multicast request sent by member.
	SIG_SENSOR_ANOMALY_REPORT           // Sensor anomaly report message.
	SIG_GNUID_TOKEN                     // GNUid Token.
	SIG_GNUID_TICKET                    // GNUid Ticket.
	SIG_CREDENTIAL                      // GNUnet credential.
)
