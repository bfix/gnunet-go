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

//nolint:stylecheck // allow non-camel-case in constants
package enums

// MsgType for GNUnet message type identifiers
//
//go:generate stringer -type=MsgType
type MsgType uint16

// GNUnet message types
const (
	MSG_TEST   MsgType = 1 // Test if service is online (deprecated)
	MSG_DUMMY  MsgType = 2 // Dummy messages for testing / benchmarking
	MSG_DUMMY2 MsgType = 3 // Another dummy messages for testing / benchmarking

	//------------------------------------------------------------------
	// RESOLVER message types
	//------------------------------------------------------------------

	MSG_RESOLVER_REQUEST  MsgType = 4 // Request DNS resolution
	MSG_RESOLVER_RESPONSE MsgType = 5 // Response to a DNS resolution request

	//------------------------------------------------------------------
	// AGPL source code download
	//------------------------------------------------------------------

	MSG_REQUEST_AGPL  MsgType = 6 // Message to request source code link
	MSG_RESPONSE_AGPL MsgType = 7 // Source code link

	//------------------------------------------------------------------
	// ARM message types
	//------------------------------------------------------------------

	MSG_ARM_START       MsgType = 8  // Request to ARM to start a service
	MSG_ARM_STOP        MsgType = 9  // Request to ARM to stop a service
	MSG_ARM_RESULT      MsgType = 10 // Response from ARM
	MSG_ARM_STATUS      MsgType = 11 // Status update from ARM
	MSG_ARM_LIST        MsgType = 12 // Request to ARM to list all currently running services
	MSG_ARM_LIST_RESULT MsgType = 13 // Response from ARM for listing currently running services
	MSG_ARM_MONITOR     MsgType = 14 // Request to ARM to notify client of service status changes
	MSG_ARM_TEST        MsgType = 15 // Test if ARM service is online

	//------------------------------------------------------------------
	// HELLO message types
	//------------------------------------------------------------------

	MSG_HELLO_LEGACY MsgType = 16 // Deprecated HELLO message
	MSG_HELLO        MsgType = 17 // HELLO message with friend_only flag

	//------------------------------------------------------------------
	// FRAGMENTATION message types
	//------------------------------------------------------------------

	MSG_FRAGMENT     MsgType = 18 // FRAGMENT of a larger message
	MSG_FRAGMENT_ACK MsgType = 19 // Acknowledgement of a FRAGMENT of a larger message

	//------------------------------------------------------------------
	// Transport-WLAN message types
	//------------------------------------------------------------------

	MSG_WLAN_DATA_TO_HELPER   MsgType = 39 // Type of data messages from the plugin to the gnunet-wlan-helper
	MSG_WLAN_DATA_FROM_HELPER MsgType = 40 // Type of data messages from the gnunet-wlan-helper to the plugin
	MSG_WLAN_HELPER_CONTROL   MsgType = 41 // Control message between the gnunet-wlan-helper and the daemon (with the MAC)
	MSG_WLAN_ADVERTISEMENT    MsgType = 42 // Type of messages for advertisement over wlan
	MSG_WLAN_DATA             MsgType = 43 // Type of messages for data over the wlan

	//------------------------------------------------------------------
	// Transport-DV message types
	//------------------------------------------------------------------

	MSG_DV_RECV              MsgType = 44 // DV service to DV Plugin message
	MSG_DV_SEND              MsgType = 45 // DV Plugin to DV service message
	MSG_DV_SEND_ACK          MsgType = 46 // Confirmation or failure of a DV_SEND message
	MSG_DV_ROUTE             MsgType = 47 // P2P DV message encapsulating some real message
	MSG_DV_START             MsgType = 48 // DV Plugin to DV service message, indicating startup.
	MSG_DV_CONNECT           MsgType = 49 // P2P DV message telling plugin that a peer connected
	MSG_DV_DISCONNECT        MsgType = 50 // P2P DV message telling plugin that a peer disconnected
	MSG_DV_SEND_NACK         MsgType = 51 // P2P DV message telling plugin that a message transmission failed (negative ACK)
	MSG_DV_DISTANCE_CHANGED  MsgType = 52 // P2P DV message telling plugin that our distance to a peer changed
	MSG_DV_BOX               MsgType = 53 // DV message box for boxing multiple messages.
	MSG_TRANSPORT_XU_MESSAGE MsgType = 55 // Experimental message type.

	//------------------------------------------------------------------
	// Transport-UDP message types
	//------------------------------------------------------------------

	MSG_TRANSPORT_UDP_MESSAGE MsgType = 56 // Normal UDP message type.
	MSG_TRANSPORT_UDP_ACK     MsgType = 57 // UDP ACK.

	//------------------------------------------------------------------
	// Transport-TCP message types
	//------------------------------------------------------------------

	MSG_TRANSPORT_TCP_NAT_PROBE MsgType = 60 // TCP NAT probe message
	MSG_TRANSPORT_TCP_WELCOME   MsgType = 61 // Welcome message between TCP transports.
	MSG_TRANSPORT_ATS           MsgType = 62 // Message to force transport to update bandwidth assignment (LEGACY)

	//------------------------------------------------------------------
	// NAT message types
	//------------------------------------------------------------------

	MSG_NAT_TEST MsgType = 63 // Message to ask NAT server to perform traversal test

	//------------------------------------------------------------------
	// CORE message types
	//------------------------------------------------------------------

	MSG_CORE_INIT                 MsgType = 64 // Initial setup message from core client to core.
	MSG_CORE_INIT_REPLY           MsgType = 65 // Response from core to core client to INIT message.
	MSG_CORE_NOTIFY_CONNECT       MsgType = 67 // Notify clients about new peer-to-peer connections (triggered after key exchange).
	MSG_CORE_NOTIFY_DISCONNECT    MsgType = 68 // Notify clients about peer disconnecting.
	MSG_CORE_NOTIFY_STATUS_CHANGE MsgType = 69 // Notify clients about peer status change.
	MSG_CORE_NOTIFY_INBOUND       MsgType = 70 // Notify clients about incoming P2P messages.
	MSG_CORE_NOTIFY_OUTBOUND      MsgType = 71 // Notify clients about outgoing P2P transmissions.
	MSG_CORE_SEND_REQUEST         MsgType = 74 // Request from client to transmit message.
	MSG_CORE_SEND_READY           MsgType = 75 // Confirmation from core that message can now be sent
	MSG_CORE_SEND                 MsgType = 76 // Client with message to transmit (after SEND_READY confirmation was received).
	MSG_CORE_MONITOR_PEERS        MsgType = 78 // Request for connection monitoring from CORE service.
	MSG_CORE_MONITOR_NOTIFY       MsgType = 79 // Reply for monitor by CORE service.
	MSG_CORE_ENCRYPTED_MESSAGE    MsgType = 82 // Encapsulation for an encrypted message between peers.
	MSG_CORE_PING                 MsgType = 83 // Check that other peer is alive (challenge).
	MSG_CORE_PONG                 MsgType = 84 // Confirmation that other peer is alive.
	MSG_CORE_HANGUP               MsgType = 85 // Request by the other peer to terminate the connection.
	MSG_CORE_COMPRESSED_TYPE_MAP  MsgType = 86 // gzip-compressed type map of the sender
	MSG_CORE_BINARY_TYPE_MAP      MsgType = 87 // uncompressed type map of the sender
	MSG_CORE_EPHEMERAL_KEY        MsgType = 88 // Session key exchange between peers.
	MSG_CORE_CONFIRM_TYPE_MAP     MsgType = 89 // Other peer confirms having received the type map

	//------------------------------------------------------------------
	// DATASTORE message types
	//------------------------------------------------------------------

	MSG_DATASTORE_RESERVE            MsgType = 92  // Message sent by datastore client on join.
	MSG_DATASTORE_RELEASE_RESERVE    MsgType = 93  // Message sent by datastore client on join.
	MSG_DATASTORE_STATUS             MsgType = 94  // Message sent by datastore to client informing about status processing a request (in response to RESERVE, RELEASE_RESERVE, PUT, UPDATE and REMOVE requests).
	MSG_DATASTORE_PUT                MsgType = 95  // Message sent by datastore client to store data.
	MSG_DATASTORE_GET                MsgType = 97  // Message sent by datastore client to get data.
	MSG_DATASTORE_GET_REPLICATION    MsgType = 98  // Message sent by datastore client to get random data.
	MSG_DATASTORE_GET_ZERO_ANONYMITY MsgType = 99  // Message sent by datastore client to get random data.
	MSG_DATASTORE_DATA               MsgType = 100 // Message sent by datastore to client providing requested data (in response to GET or GET_RANDOM request).
	MSG_DATASTORE_DATA_END           MsgType = 101 // Message sent by datastore to client signaling end of matching data. This message will also be sent for "GET_RANDOM", even though "GET_RANDOM" returns at most one data item.
	MSG_DATASTORE_REMOVE             MsgType = 102 // Message sent by datastore client to remove data.
	MSG_DATASTORE_DROP               MsgType = 103 // Message sent by datastore client to drop the database.
	MSG_DATASTORE_GET_KEY            MsgType = 104 // Message sent by datastore client to get data by key.

	//------------------------------------------------------------------
	// FS message types
	//------------------------------------------------------------------

	MSG_FS_REQUEST_LOC_SIGN      MsgType = 126 // Message sent by fs client to request LOC signature.
	MSG_FS_REQUEST_LOC_SIGNATURE MsgType = 127 // Reply sent by fs service with LOC signature.
	MSG_FS_INDEX_START           MsgType = 128 // Message sent by fs client to start indexing.
	MSG_FS_INDEX_START_OK        MsgType = 129 // Affirmative response to a request for start indexing.
	MSG_FS_INDEX_START_FAILED    MsgType = 130 // Response to a request for start indexing that refuses.
	MSG_FS_INDEX_LIST_GET        MsgType = 131 // Request from client for list of indexed files.
	MSG_FS_INDEX_LIST_ENTRY      MsgType = 132 // Reply to client with an indexed file name.
	MSG_FS_INDEX_LIST_END        MsgType = 133 // Reply to client indicating end of list.
	MSG_FS_UNINDEX               MsgType = 134 // Request from client to unindex a file.
	MSG_FS_UNINDEX_OK            MsgType = 135 // Reply to client indicating unindex receipt.
	MSG_FS_START_SEARCH          MsgType = 136 // Client asks FS service to start a (keyword) search.
	MSG_FS_GET                   MsgType = 137 // P2P request for content (one FS to another).
	MSG_FS_PUT                   MsgType = 138 // P2P response with content or active migration of content.  Also used between the service and clients (in response to #FS_START_SEARCH).
	MSG_FS_MIGRATION_STOP        MsgType = 139 // Peer asks us to stop migrating content towards it for a while.
	MSG_FS_CADET_QUERY           MsgType = 140 // P2P request for content (one FS to another via a cadet).
	MSG_FS_CADET_REPLY           MsgType = 141 // P2P answer for content (one FS to another via a cadet).

	//------------------------------------------------------------------
	// DHT message types
	//------------------------------------------------------------------

	MSG_DHT_CLIENT_PUT               MsgType = 142 // Client wants to store item in DHT.
	MSG_DHT_CLIENT_GET               MsgType = 143 // Client wants to lookup item in DHT.
	MSG_DHT_CLIENT_GET_STOP          MsgType = 144 // Client wants to stop search in DHT.
	MSG_DHT_CLIENT_RESULT            MsgType = 145 // Service returns result to client.
	MSG_DHT_P2P_PUT                  MsgType = 146 // Peer is storing data in DHT.
	MSG_DHT_P2P_GET                  MsgType = 147 // Peer tries to find data in DHT.
	MSG_DHT_P2P_RESULT               MsgType = 148 // Data is returned to peer from DHT.
	MSG_DHT_MONITOR_GET              MsgType = 149 // Receive information about transiting GETs
	MSG_DHT_MONITOR_GET_RESP         MsgType = 150 // Receive information about transiting GET responses
	MSG_DHT_MONITOR_PUT              MsgType = 151 // Receive information about transiting PUTs
	MSG_DHT_MONITOR_PUT_RESP         MsgType = 152 // Receive information about transiting PUT responses (TODO)
	MSG_DHT_MONITOR_START            MsgType = 153 // Request information about transiting messages
	MSG_DHT_MONITOR_STOP             MsgType = 154 // Stop information about transiting messages
	MSG_DHT_CLIENT_GET_RESULTS_KNOWN MsgType = 156 // Certain results are already known to the client, filter those.
	MSG_DHT_P2P_HELLO                MsgType = 157 // HELLO advertising a neighbours addresses.
	MSG_DHT_CORE                     MsgType = 158 // Encapsulation of DHT messages in CORE service.
	MSG_DHT_CLIENT_HELLO_URL         MsgType = 159 // HELLO URL send between client and service (in either direction).
	MSG_DHT_CLIENT_HELLO_GET         MsgType = 161 // Client requests DHT service's HELLO URL.

	//------------------------------------------------------------------
	// HOSTLIST message types
	//------------------------------------------------------------------

	MSG_HOSTLIST_ADVERTISEMENT MsgType = 160 // Hostlist advertisement message

	//------------------------------------------------------------------
	// STATISTICS message types
	//------------------------------------------------------------------

	MSG_STATISTICS_SET                MsgType = 168 // Set a statistical value.
	MSG_STATISTICS_GET                MsgType = 169 // Get a statistical value(s).
	MSG_STATISTICS_VALUE              MsgType = 170 // Response to a STATISTICS_GET message (with value).
	MSG_STATISTICS_END                MsgType = 171 // Response to a STATISTICS_GET message (end of value stream).
	MSG_STATISTICS_WATCH              MsgType = 172 // Watch changes to a statistical value.  Message format is the same as for GET, except that the subsystem and entry name must be given.
	MSG_STATISTICS_WATCH_VALUE        MsgType = 173 // Changes to a watched value.
	MSG_STATISTICS_DISCONNECT         MsgType = 174 // Client is done sending service requests and will now disconnect.
	MSG_STATISTICS_DISCONNECT_CONFIRM MsgType = 175 // Service confirms disconnect and that it is done processing all requests from the client.

	//------------------------------------------------------------------
	// VPN message types
	//------------------------------------------------------------------

	MSG_VPN_HELPER                     MsgType = 185 // Type of messages between the gnunet-vpn-helper and the daemon
	MSG_VPN_ICMP_TO_SERVICE            MsgType = 190 // ICMP packet for a service.
	MSG_VPN_ICMP_TO_INTERNET           MsgType = 191 // ICMP packet for the Internet.
	MSG_VPN_ICMP_TO_VPN                MsgType = 192 // ICMP packet for the VPN
	MSG_VPN_DNS_TO_INTERNET            MsgType = 193 // DNS request for a DNS exit service.
	MSG_VPN_DNS_FROM_INTERNET          MsgType = 194 // DNS reply from a DNS exit service.
	MSG_VPN_TCP_TO_SERVICE_START       MsgType = 195 // TCP packet for a service.
	MSG_VPN_TCP_TO_INTERNET_START      MsgType = 196 // TCP packet for the Internet.
	MSG_VPN_TCP_DATA_TO_EXIT           MsgType = 197 // TCP packet of an established connection.
	MSG_VPN_TCP_DATA_TO_VPN            MsgType = 198 // TCP packet of an established connection.
	MSG_VPN_UDP_TO_SERVICE             MsgType = 199 // UDP packet for a service.
	MSG_VPN_UDP_TO_INTERNET            MsgType = 200 // UDP packet for the Internet.
	MSG_VPN_UDP_REPLY                  MsgType = 201 // UDP packet from a remote host
	MSG_VPN_CLIENT_REDIRECT_TO_IP      MsgType = 202 // Client asks VPN service to setup an IP to redirect traffic via an exit node to some global IP address.
	MSG_VPN_CLIENT_REDIRECT_TO_SERVICE MsgType = 203 // Client asks VPN service to setup an IP to redirect traffic to some peer offering a service.
	MSG_VPN_CLIENT_USE_IP              MsgType = 204 // VPN service responds to client with an IP to use for the requested redirection.

	//------------------------------------------------------------------
	// VPN-DNS message types
	//------------------------------------------------------------------

	MSG_DNS_CLIENT_INIT     MsgType = 211 // Initial message from client to DNS service for registration.
	MSG_DNS_CLIENT_REQUEST  MsgType = 212 // Type of messages between the gnunet-helper-dns and the service
	MSG_DNS_CLIENT_RESPONSE MsgType = 213 // Type of messages between the gnunet-helper-dns and the service
	MSG_DNS_HELPER          MsgType = 214 // Type of messages between the gnunet-helper-dns and the service

	//------------------------------------------------------------------
	// CHAT message types START
	//------------------------------------------------------------------

	MSG_CHAT_JOIN_REQUEST              MsgType = 300 // Message sent from client to join a chat room.
	MSG_CHAT_JOIN_NOTIFICATION         MsgType = 301 // Message sent to client to indicate joining of another room member.
	MSG_CHAT_LEAVE_NOTIFICATION        MsgType = 302 // Message sent to client to indicate leaving of another room member.
	MSG_CHAT_MESSAGE_NOTIFICATION      MsgType = 303 // Notification sent by service to client indicating that we've received a chat message.
	MSG_CHAT_TRANSMIT_REQUEST          MsgType = 304 // Request sent by client to transmit a chat message to another room members.
	MSG_CHAT_CONFIRMATION_RECEIPT      MsgType = 305 // Receipt sent from a message receiver to the service to confirm delivery of a chat message.
	MSG_CHAT_CONFIRMATION_NOTIFICATION MsgType = 306 // Notification sent from the service to the original sender to acknowledge delivery of a chat message.
	MSG_CHAT_P2P_JOIN_NOTIFICATION     MsgType = 307 // P2P message sent to indicate joining of another room member.
	MSG_CHAT_P2P_LEAVE_NOTIFICATION    MsgType = 308 // P2P message sent to indicate leaving of another room member.
	MSG_CHAT_P2P_SYNC_REQUEST          MsgType = 309 // P2P message sent to a newly connected peer to request its known clients in order to synchronize room members.
	MSG_CHAT_P2P_MESSAGE_NOTIFICATION  MsgType = 310 // Notification sent from one peer to another to indicate that we have received a chat message.
	MSG_CHAT_P2P_CONFIRMATION_RECEIPT  MsgType = 311 // P2P receipt confirming delivery of a chat message.

	//------------------------------------------------------------------
	// NSE (network size estimation) message types
	//------------------------------------------------------------------

	MSG_NSE_START     MsgType = 321 // client->service message indicating start
	MSG_NSE_P2P_FLOOD MsgType = 322 // P2P message sent from nearest peer
	MSG_NSE_ESTIMATE  MsgType = 323 // service->client message indicating

	//------------------------------------------------------------------
	// PEERINFO message types
	//------------------------------------------------------------------

	MSG_PEERINFO_GET      MsgType = 330 // Request update and listing of a peer
	MSG_PEERINFO_GET_ALL  MsgType = 331 // Request update and listing of all peers
	MSG_PEERINFO_INFO     MsgType = 332 // Information about one of the peers
	MSG_PEERINFO_INFO_END MsgType = 333 // End of information about other peers
	MSG_PEERINFO_NOTIFY   MsgType = 334 // Start notifying this client about changes

	//------------------------------------------------------------------
	// ATS message types
	//------------------------------------------------------------------

	MSG_ATS_START                  MsgType = 340 // Type of the 'struct ClientStartMessage' sent by clients to ATS to identify the type of the client.
	MSG_ATS_REQUEST_ADDRESS        MsgType = 341 // Type of the 'struct RequestAddressMessage' sent by clients to request an address to help connect.
	MSG_ATS_REQUEST_ADDRESS_CANCEL MsgType = 342 // Type of the 'struct RequestAddressMessage' sent by clients to request an address to help connect.
	MSG_ATS_ADDRESS_UPDATE         MsgType = 343 // Type of the 'struct AddressUpdateMessage' sent by clients to ATS to inform ATS about performance changes.
	MSG_ATS_ADDRESS_DESTROYED      MsgType = 344 // Type of the 'struct AddressDestroyedMessage' sent by clients to ATS  to inform ATS about an address being unavailable.
	MSG_ATS_ADDRESS_SUGGESTION     MsgType = 345 // Type of the 'struct AddressSuggestionMessage' sent by ATS to clients to suggest switching to a different address.
	MSG_ATS_PEER_INFORMATION       MsgType = 346 // Type of the 'struct PeerInformationMessage' sent by ATS to clients to inform about QoS for a particular connection.
	MSG_ATS_RESERVATION_REQUEST    MsgType = 347 // Type of the 'struct ReservationRequestMessage' sent by clients to ATS to ask for inbound bandwidth reservations.
	MSG_ATS_RESERVATION_RESULT     MsgType = 348 // Type of the 'struct ReservationResultMessage' sent by ATS to clients  in response to a reservation request.
	MSG_ATS_PREFERENCE_CHANGE      MsgType = 349 // Type of the 'struct ChangePreferenceMessage' sent by clients to ATS to ask for allocation preference changes.
	MSG_ATS_SESSION_RELEASE        MsgType = 350 // Type of the 'struct SessionReleaseMessage' sent by ATS to client to confirm that a session ID was destroyed.
	MSG_ATS_ADDRESS_ADD            MsgType = 353 // Type of the 'struct AddressUpdateMessage' sent by client to ATS to add a new address
	MSG_ATS_ADDRESSLIST_REQUEST    MsgType = 354 // Type of the 'struct AddressListRequestMessage' sent by client to ATS to request information about addresses
	MSG_ATS_ADDRESSLIST_RESPONSE   MsgType = 355 // Type of the 'struct AddressListResponseMessage' sent by ATS to client with information about addresses
	MSG_ATS_PREFERENCE_FEEDBACK    MsgType = 356 // Type of the 'struct ChangePreferenceMessage' sent by clients to ATS to ask for allocation preference changes.

	//------------------------------------------------------------------
	// TRANSPORT message types
	//------------------------------------------------------------------

	MSG_TRANSPORT_START                      MsgType = 360 // Message from the core saying that the transport server should start giving it messages. This should automatically trigger the transmission of a HELLO message.
	MSG_TRANSPORT_CONNECT                    MsgType = 361 // Message from TRANSPORT notifying about a client that connected to us.
	MSG_TRANSPORT_DISCONNECT                 MsgType = 362 // Message from TRANSPORT notifying about a client that disconnected from us.
	MSG_TRANSPORT_SEND                       MsgType = 363 // Request to TRANSPORT to transmit a message.
	MSG_TRANSPORT_SEND_OK                    MsgType = 364 // Confirmation from TRANSPORT that message for transmission has been queued (and that the next message to this peer can now be passed to the service).  Note that this confirmation does NOT imply that the message was fully transmitted.
	MSG_TRANSPORT_RECV                       MsgType = 365 // Message from TRANSPORT notifying about a message that was received.
	MSG_TRANSPORT_SET_QUOTA                  MsgType = 366 // Message telling transport to limit its receive rate.
	MSG_TRANSPORT_ADDRESS_TO_STRING          MsgType = 367 // Request to look addresses of peers in server.
	MSG_TRANSPORT_ADDRESS_TO_STRING_REPLY    MsgType = 368 // Response to the address lookup request.
	MSG_TRANSPORT_BLACKLIST_INIT             MsgType = 369 // Register a client that wants to do blacklisting.
	MSG_TRANSPORT_BLACKLIST_QUERY            MsgType = 370 // Query to a blacklisting client (is this peer blacklisted)?
	MSG_TRANSPORT_BLACKLIST_REPLY            MsgType = 371 // Reply from blacklisting client (answer to blacklist query).
	MSG_TRANSPORT_PING                       MsgType = 372 // Transport PING message
	MSG_TRANSPORT_PONG                       MsgType = 373 // Transport PONG message
	MSG_TRANSPORT_SESSION_SYN                MsgType = 375 // Transport SYN message exchanged between transport services to indicate that a session should be marked as 'connected'.
	MSG_TRANSPORT_SESSION_SYN_ACK            MsgType = 376 // Transport SYN_ACK message exchanged between transport services to indicate that a SYN message was accepted
	MSG_TRANSPORT_SESSION_ACK                MsgType = 377 // Transport ACK message exchanged between transport services to indicate that a SYN_ACK message was accepted
	MSG_TRANSPORT_SESSION_DISCONNECT         MsgType = 378 // Transport DISCONNECT message exchanged between transport services to indicate that a connection should be dropped.
	MSG_TRANSPORT_SESSION_QUOTA              MsgType = 379 // Message exchanged between transport services to indicate that the sender should limit its transmission rate to the indicated quota.
	MSG_TRANSPORT_MONITOR_PEER_REQUEST       MsgType = 380 // Request to monitor addresses used by a peer or all peers.
	MSG_TRANSPORT_SESSION_KEEPALIVE          MsgType = 381 // Message send by a peer to notify the other to keep the session alive and measure latency in a regular interval
	MSG_TRANSPORT_SESSION_KEEPALIVE_RESPONSE MsgType = 382 // Response to a #TRANSPORT_SESSION_KEEPALIVE message to measure latency in a regular interval
	MSG_TRANSPORT_MONITOR_PEER_RESPONSE      MsgType = 383 // Response to #TRANSPORT_MONITOR_PEER_REQUEST request to iterate over all known addresses.
	MSG_TRANSPORT_BROADCAST_BEACON           MsgType = 384 // Message send by a peer to notify the other to keep the session alive.
	MSG_TRANSPORT_TRAFFIC_METRIC             MsgType = 385 // Message containing traffic metrics for transport service
	MSG_TRANSPORT_MONITOR_PLUGIN_START       MsgType = 388 // Request to start monitoring the connection state of plugins.
	MSG_TRANSPORT_MONITOR_PLUGIN_EVENT       MsgType = 389 // Monitoring event about the connection state of plugins, generated in response to a subscription initiated via #TRANSPORT_MONITOR_PLUGIN_START
	MSG_TRANSPORT_MONITOR_PLUGIN_SYNC        MsgType = 390 // Monitoring event notifying client that the initial iteration is now completed and we are in sync with the state of the subsystem.
	MSG_TRANSPORT_MONITOR_PEER_RESPONSE_END  MsgType = 391 // terminating list of replies.

	//------------------------------------------------------------------
	// FS-PUBLISH-HELPER IPC Messages
	//------------------------------------------------------------------

	MSG_FS_PUBLISH_HELPER_PROGRESS_FILE      MsgType = 420 // Progress information from the helper: found a file
	MSG_FS_PUBLISH_HELPER_PROGRESS_DIRECTORY MsgType = 421 // Progress information from the helper: found a directory
	MSG_FS_PUBLISH_HELPER_ERROR              MsgType = 422 // Error signal from the helper.
	MSG_FS_PUBLISH_HELPER_SKIP_FILE          MsgType = 423 // Signal that helper skipped a file.
	MSG_FS_PUBLISH_HELPER_COUNTING_DONE      MsgType = 424 // Signal that helper is done scanning the directory tree.
	MSG_FS_PUBLISH_HELPER_META_DATA          MsgType = 425 // Extracted meta data from the helper.
	MSG_FS_PUBLISH_HELPER_FINISHED           MsgType = 426 // Signal that helper is done.

	//------------------------------------------------------------------
	// NAMECACHE message types
	//------------------------------------------------------------------

	MSG_NAMECACHE_LOOKUP_BLOCK          MsgType = 431 // Client to service: lookup block
	MSG_NAMECACHE_LOOKUP_BLOCK_RESPONSE MsgType = 432 // Service to client: result of block lookup
	MSG_NAMECACHE_BLOCK_CACHE           MsgType = 433 // Client to service: cache a block
	MSG_NAMECACHE_BLOCK_CACHE_RESPONSE  MsgType = 434 // Service to client: result of block cache request

	//------------------------------------------------------------------
	// NAMESTORE message types
	//------------------------------------------------------------------

	MSG_NAMESTORE_RECORD_STORE           MsgType = 435  // Client to service: store records (as authority)
	MSG_NAMESTORE_RECORD_STORE_RESPONSE  MsgType = 436  // Service to client: result of store operation.
	MSG_NAMESTORE_RECORD_LOOKUP          MsgType = 437  // Client to service: lookup label
	MSG_NAMESTORE_RECORD_LOOKUP_RESPONSE MsgType = 438  // Service to client: lookup label
	MSG_NAMESTORE_ZONE_TO_NAME           MsgType = 439  // Client to service: "reverse" lookup for zone name based on zone key
	MSG_NAMESTORE_ZONE_TO_NAME_RESPONSE  MsgType = 440  // Service to client: result of zone-to-name lookup.
	MSG_NAMESTORE_MONITOR_START          MsgType = 441  // Client to service: start monitoring (yields sequence of "ZONE_ITERATION_RESPONSES" --- forever).
	MSG_NAMESTORE_MONITOR_SYNC           MsgType = 442  // Service to client: you're now in sync.
	MSG_NAMESTORE_RECORD_RESULT          MsgType = 443  // Service to client: here is a (plaintext) record you requested.
	MSG_NAMESTORE_MONITOR_NEXT           MsgType = 444  // Client to service: I am now ready for the next (set of) monitor events. Monitoring equivalent of #NAMESTORE_ZONE_ITERATION_NEXT.
	MSG_NAMESTORE_ZONE_ITERATION_START   MsgType = 445  // Client to service: please start iteration; receives "NAMESTORE_LOOKUP_NAME_RESPONSE" messages in return.
	MSG_NAMESTORE_ZONE_ITERATION_NEXT    MsgType = 447  // Client to service: next record(s) in iteration please.
	MSG_NAMESTORE_ZONE_ITERATION_STOP    MsgType = 448  // Client to service: stop iterating.
	MSG_NAMESTORE_ZONE_ITERATION_END     MsgType = 449  // Service to client: done iterating.
	MSG_NAMESTORE_TX_CONTROL             MsgType = 1750 // Begin, Commit or Rollback
	MSG_NAMESTORE_TX_CONTROL_RESULT      MsgType = 1751 // status message for control message
	MSG_NAMESTORE_RECORD_EDIT            MsgType = 1752 // open and lock records for editing message

	//------------------------------------------------------------------
	// LOCKMANAGER message types
	//------------------------------------------------------------------

	MSG_LOCKMANAGER_ACQUIREMsgType MsgType = 450 // Message to acquire Lock
	MSG_LOCKMANAGER_RELEASEMsgType MsgType = 451 // Message to release lock
	MSG_LOCKMANAGER_SUCCESSMsgType MsgType = 452 // SUCCESS reply from lockmanager

	//------------------------------------------------------------------
	// TESTBED message types
	//------------------------------------------------------------------

	MSG_TESTBED_INIT                      MsgType = 460 // Initial message from a client to a testing control service
	MSG_TESTBED_ADD_HOST                  MsgType = 461 // Message to add host
	MSG_TESTBED_ADD_HOST_SUCCESS          MsgType = 462 // Message to signal that a add host succeeded
	MSG_TESTBED_LINK_CONTROLLERS          MsgType = 463 // Message to link delegated controller to slave controller
	MSG_TESTBED_CREATE_PEER               MsgType = 464 // Message to create a peer at a host
	MSG_TESTBED_RECONFIGURE_PEER          MsgType = 465 // Message to reconfigure a peer
	MSG_TESTBED_START_PEER                MsgType = 466 // Message to start a peer at a host
	MSG_TESTBED_STOP_PEER                 MsgType = 467 // Message to stop a peer at a host
	MSG_TESTBED_DESTROY_PEER              MsgType = 468 // Message to destroy a peer
	MSG_TESTBED_CONFIGURE_UNDERLAY_LINK   MsgType = 469 // Configure underlay link message
	MSG_TESTBED_OVERLAY_CONNECT           MsgType = 470 // Message to connect peers in a overlay
	MSG_TESTBED_PEER_EVENT                MsgType = 471 // Message for peer events
	MSG_TESTBED_PEER_CONNECT_EVENT        MsgType = 472 // Message for peer connect events
	MSG_TESTBED_OPERATION_FAIL_EVENT      MsgType = 473 // Message for operation events
	MSG_TESTBED_CREATE_PEER_SUCCESS       MsgType = 474 // Message to signal successful peer creation
	MSG_TESTBED_GENERIC_OPERATION_SUCCESS MsgType = 475 // Message to signal a generic operation has been successful
	MSG_TESTBED_GET_PEER_INFORMATION      MsgType = 476 // Message to get a peer's information
	MSG_TESTBED_PEER_INFORMATION          MsgType = 477 // Message containing the peer's information
	MSG_TESTBED_REMOTE_OVERLAY_CONNECT    MsgType = 478 // Message to request a controller to make one of its peer to connect to another peer using the contained HELLO
	MSG_TESTBED_GET_SLAVE_CONFIGURATION   MsgType = 479 // Message to request configuration of a slave controller
	MSG_TESTBED_SLAVE_CONFIGURATION       MsgType = 480 // Message which contains the configuration of slave controller
	MSG_TESTBED_LINK_CONTROLLERS_RESULT   MsgType = 481 // Message to signal the result of #TESTBED_LINK_CONTROLLERS request
	MSG_TESTBED_SHUTDOWN_PEERS            MsgType = 482 // A controller receiving this message floods it to its directly-connected sub-controllers and then stops and destroys all peers
	MSG_TESTBED_MANAGE_PEER_SERVICE       MsgType = 483 // Message to start/stop a service of a peer
	MSG_TESTBED_BARRIER_INIT              MsgType = 484 // Message to initialise a barrier.  Messages of these type are flooded to all sub-controllers
	MSG_TESTBED_BARRIER_CANCEL            MsgType = 485 // Message to cancel a barrier.  This message is flooded to all sub-controllers
	MSG_TESTBED_BARRIER_STATUS            MsgType = 486 // Message for signalling status of a barrier
	MSG_TESTBED_BARRIER_WAIT              MsgType = 487 // Message sent by a peer when it has reached a barrier and is waiting for it to be crossed
	MSG_TESTBED_MAX                       MsgType = 488 // Not really a message, but for careful checks on the testbed messages; Should always be the maximum and never be used to send messages with this type
	MSG_TESTBED_HELPER_INIT               MsgType = 495 // The initialization message towards gnunet-testbed-helper
	MSG_TESTBED_HELPER_REPLY              MsgType = 496 // The reply message from gnunet-testbed-helper

	//------------------------------------------------------------------
	// GNS.
	//------------------------------------------------------------------

	MSG_GNS_LOOKUP                MsgType = 500 // Client would like to resolve a name.
	MSG_GNS_LOOKUP_RESULT         MsgType = 501 // Service response to name resolution request from client.
	MSG_GNS_REVERSE_LOOKUP        MsgType = 502 // Reverse lookup
	MSG_GNS_REVERSE_LOOKUP_RESULT MsgType = 503 // Response to reverse lookup

	//------------------------------------------------------------------
	// CONSENSUS message types
	//------------------------------------------------------------------

	MSG_CONSENSUS_CLIENT_JOIN             MsgType = 520 // Join a consensus session. Sent by client to service as first message.
	MSG_CONSENSUS_CLIENT_INSERT           MsgType = 521 // Insert an element. Sent by client to service.
	MSG_CONSENSUS_CLIENT_BEGIN            MsgType = 522 // Begin accepting new elements from other participants. Sent by client to service.
	MSG_CONSENSUS_CLIENT_RECEIVED_ELEMENT MsgType = 523 // Sent by service when a new element is added.
	MSG_CONSENSUS_CLIENT_CONCLUDE         MsgType = 524 // Sent by client to service in order to start the consensus conclusion.
	MSG_CONSENSUS_CLIENT_CONCLUDE_DONE    MsgType = 525 // Sent by service to client in order to signal a completed consensus conclusion. Last message sent in a consensus session.
	MSG_CONSENSUS_CLIENT_ACK              MsgType = 540 // Sent by client to service, telling whether a received element should be accepted and propagated further or not.
	MSG_CONSENSUS_P2P_DELTA_ESTIMATE      MsgType = 541 // Strata estimator.
	MSG_CONSENSUS_P2P_DIFFERENCE_DIGEST   MsgType = 542 // IBF containing all elements of a peer.
	MSG_CONSENSUS_P2P_ELEMENTS            MsgType = 543 // One or more elements that are sent from peer to peer.
	MSG_CONSENSUS_P2P_ELEMENTS_REQUEST    MsgType = 544 // Elements, and requests for further elements
	MSG_CONSENSUS_P2P_ELEMENTS_REPORT     MsgType = 545 // Elements that a peer reports to be missing at the remote peer.
	MSG_CONSENSUS_P2P_HELLO               MsgType = 546 // Initialization message for consensus p2p communication.
	MSG_CONSENSUS_P2P_SYNCED              MsgType = 547 // Report that the peer is synced with the partner after successfully decoding the invertible bloom filter.
	MSG_CONSENSUS_P2P_FIN                 MsgType = 548 // Interaction os over, got synched and reported all elements
	MSG_CONSENSUS_P2P_ABORT               MsgType = 548 // Abort a round, don't send requested elements anymore
	MSG_CONSENSUS_P2P_ROUND_CONTEXT       MsgType = 547 // Abort a round, don't send requested elements anymore

	//------------------------------------------------------------------
	// SET message types
	//------------------------------------------------------------------

	MSG_SET_UNION_P2P_REQUEST_FULL        MsgType = 565 // Demand the whole element from the other peer, given only the hash code.
	MSG_SET_UNION_P2P_DEMAND              MsgType = 566 // Demand the whole element from the other peer, given only the hash code.
	MSG_SET_UNION_P2P_INQUIRY             MsgType = 567 // Tell the other peer to send us a list of hashes that match an IBF key.
	MSG_SET_UNION_P2P_OFFER               MsgType = 568 // Tell the other peer which hashes match a given IBF key.
	MSG_SET_REJECT                        MsgType = 569 // Reject a set request.
	MSG_SET_CANCEL                        MsgType = 570 // Cancel a set operation
	MSG_SET_ITER_ACK                      MsgType = 571 // Acknowledge result from iteration
	MSG_SET_RESULT                        MsgType = 572 // Create an empty set
	MSG_SET_ADD                           MsgType = 573 // Add element to set
	MSG_SET_REMOVE                        MsgType = 574 // Remove element from set
	MSG_SET_LISTEN                        MsgType = 575 // Listen for operation requests
	MSG_SET_ACCEPT                        MsgType = 576 // Accept a set request
	MSG_SET_EVALUATE                      MsgType = 577 // Evaluate a set operation
	MSG_SET_CONCLUDE                      MsgType = 578 // Start a set operation with the given set
	MSG_SET_REQUEST                       MsgType = 579 // Notify the client of a request from a remote peer
	MSG_SET_CREATE                        MsgType = 580 // Create a new local set
	MSG_SET_P2P_OPERATION_REQUEST         MsgType = 581 // Request a set operation from a remote peer.
	MSG_SET_UNION_P2P_SE                  MsgType = 582 // Strata estimator.
	MSG_SET_UNION_P2P_IBF                 MsgType = 583 // Invertible bloom filter.
	MSG_SET_P2P_ELEMENTS                  MsgType = 584 // Actual set elements.
	MSG_SET_P2P_ELEMENT_REQUESTS          MsgType = 585 // Requests for the elements with the given hashes.
	MSG_SET_UNION_P2P_DONE                MsgType = 586 // Set operation is done.
	MSG_SET_ITER_REQUEST                  MsgType = 587 // Start iteration over set elements.
	MSG_SET_ITER_ELEMENT                  MsgType = 588 // Element result for the iterating client.
	MSG_SET_ITER_DONE                     MsgType = 589 // Iteration end marker for the client.
	MSG_SET_UNION_P2P_SEC                 MsgType = 590 // Compressed strata estimator.
	MSG_SET_INTERSECTION_P2P_ELEMENT_INFO MsgType = 591 // Information about the element count for intersection
	MSG_SET_INTERSECTION_P2P_BF           MsgType = 592 // Bloom filter message for intersection exchange started by Bob.
	MSG_SET_INTERSECTION_P2P_DONE         MsgType = 593 // Intersection operation is done.
	MSG_SET_COPY_LAZY_PREPARE             MsgType = 594 // Ask the set service to prepare a copy of a set.
	MSG_SET_COPY_LAZY_RESPONSE            MsgType = 595 // Give the client an ID for connecting to the set's copy.
	MSG_SET_COPY_LAZY_CONNECT             MsgType = 596 // Sent by the client to the server to connect to an existing, lazily copied set.
	MSG_SET_UNION_P2P_FULL_DONE           MsgType = 597 // Request all missing elements from the other peer, based on their sets and the elements we previously sent with #SET_P2P_ELEMENTS.
	MSG_SET_UNION_P2P_FULL_ELEMENT        MsgType = 598 // Send a set element, not as response to a demand but because we're sending the full set.
	MSG_SET_UNION_P2P_OVER                MsgType = 599 // Request all missing elements from the other peer, based on their sets and the elements we previously sent with #SET_P2P_ELEMENTS.

	//------------------------------------------------------------------
	// TESTBED LOGGER message types
	//------------------------------------------------------------------

	MSG_TESTBED_LOGGER_MSG MsgType = 600 // Message for TESTBED LOGGER
	MSG_TESTBED_LOGGER_ACK MsgType = 601 // Message for TESTBED LOGGER acknowledgement

	MSG_REGEX_ANNOUNCE MsgType = 620 // Advertise regex capability.
	MSG_REGEX_SEARCH   MsgType = 621 // Search for peer with matching capability.
	MSG_REGEX_RESULT   MsgType = 622 // Result in response to regex search.

	//------------------------------------------------------------------
	// IDENTITY message types
	//------------------------------------------------------------------

	MSG_IDENTITY_START          MsgType = 624 // First message send from identity client to service (to subscribe to updates).
	MSG_IDENTITY_RESULT_CODE    MsgType = 625 // Generic response from identity service with success and/or error message.
	MSG_IDENTITY_UPDATE         MsgType = 626 // Update about identity status from service to clients.
	MSG_IDENTITY_GET_DEFAULT    MsgType = 627 // Client requests to know default identity for a subsystem.
	MSG_IDENTITY_SET_DEFAULT    MsgType = 628 // Client sets default identity; or service informs about default identity.
	MSG_IDENTITY_CREATE         MsgType = 629 // Create new identity (client->service).
	MSG_IDENTITY_RENAME         MsgType = 630 // Rename existing identity (client->service).
	MSG_IDENTITY_DELETE         MsgType = 631 // Delete identity (client->service).
	MSG_IDENTITY_LOOKUP         MsgType = 632
	MSG_IDENTITY_LOOKUP_BY_NAME MsgType = 633

	//------------------------------------------------------------------
	// REVOCATION message types
	//------------------------------------------------------------------

	MSG_REVOCATION_QUERY           MsgType = 636 // Client to service: was this key revoked?
	MSG_REVOCATION_QUERY_RESPONSE  MsgType = 637 // Service to client: answer if key was revoked!
	MSG_REVOCATION_REVOKE          MsgType = 638 // Client to service OR peer-to-peer: revoke this key!
	MSG_REVOCATION_REVOKE_RESPONSE MsgType = 639 // Service to client: revocation confirmed

	//------------------------------------------------------------------
	// SCALARPRODUCT message types
	//------------------------------------------------------------------

	MSG_SCALARPRODUCT_CLIENT_TO_ALICE            MsgType = 640 // Client -> Alice
	MSG_SCALARPRODUCT_CLIENT_TO_BOB              MsgType = 641 // Client -> Bob
	MSG_SCALARPRODUCT_CLIENT_MULTIPART_ALICE     MsgType = 642 // Client -> Alice multipart
	MSG_SCALARPRODUCT_CLIENT_MULTIPART_BOB       MsgType = 643 // Client -> Bob multipart
	MSG_SCALARPRODUCT_SESSION_INITIALIZATION     MsgType = 644 // Alice -> Bob session initialization
	MSG_SCALARPRODUCT_ALICE_CRYPTODATA           MsgType = 645 // Alice -> Bob SP crypto-data (after intersection)
	MSG_SCALARPRODUCT_BOB_CRYPTODATA             MsgType = 647 // Bob -> Alice SP crypto-data
	MSG_SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART   MsgType = 648 // Bob -> Alice SP crypto-data multipart
	MSG_SCALARPRODUCT_RESULT                     MsgType = 649 // Alice/Bob -> Client Result
	MSG_SCALARPRODUCT_ECC_SESSION_INITIALIZATION MsgType = 650 // Alice -> Bob ECC session initialization
	MSG_SCALARPRODUCT_ECC_ALICE_CRYPTODATA       MsgType = 651 // Alice -> Bob ECC crypto data
	MSG_SCALARPRODUCT_ECC_BOB_CRYPTODATA         MsgType = 652 // Bob -> Alice ECC crypto data

	//------------------------------------------------------------------
	// PSYCSTORE message types
	//------------------------------------------------------------------

	MSG_PSYCSTORE_MEMBERSHIP_STORE     MsgType = 660 // Store a membership event.
	MSG_PSYCSTORE_MEMBERSHIP_TEST      MsgType = 661 // Test for membership of a member at a particular point in time.
	MSG_PSYCSTORE_FRAGMENT_STORE       MsgType = 662 //
	MSG_PSYCSTORE_FRAGMENT_GET         MsgType = 663 //
	MSG_PSYCSTORE_MESSAGE_GET          MsgType = 664 //
	MSG_PSYCSTORE_MESSAGE_GET_FRAGMENT MsgType = 665 //
	MSG_PSYCSTORE_COUNTERS_GET         MsgType = 666 //
	MSG_PSYCSTORE_STATE_MODIFY         MsgType = 668 //
	MSG_PSYCSTORE_STATE_SYNC           MsgType = 669 //
	MSG_PSYCSTORE_STATE_RESET          MsgType = 670 //
	MSG_PSYCSTORE_STATE_HASH_UPDATE    MsgType = 671 //
	MSG_PSYCSTORE_STATE_GET            MsgType = 672 //
	MSG_PSYCSTORE_STATE_GET_PREFIX     MsgType = 673 //
	MSG_PSYCSTORE_RESULT_CODE          MsgType = 674 // Generic response from PSYCstore service with success and/or error message.
	MSG_PSYCSTORE_RESULT_FRAGMENT      MsgType = 675 //
	MSG_PSYCSTORE_RESULT_COUNTERS      MsgType = 676 //
	MSG_PSYCSTORE_RESULT_STATE         MsgType = 677 //

	//------------------------------------------------------------------
	// PSYC message types
	//------------------------------------------------------------------

	MSG_PSYC_RESULT_CODE              MsgType = 680 // S->C: result of an operation
	MSG_PSYC_MASTER_START             MsgType = 681 // C->S: request to start a channel as a master
	MSG_PSYC_MASTER_START_ACK         MsgType = 682 // S->C: master start acknowledgement
	MSG_PSYC_SLAVE_JOIN               MsgType = 683 // C->S: request to join a channel as a slave
	MSG_PSYC_SLAVE_JOIN_ACK           MsgType = 684 // S->C: slave join acknowledgement
	MSG_PSYC_PART_REQUEST             MsgType = 685 // C->S: request to part from a channel
	MSG_PSYC_PART_ACK                 MsgType = 686 // S->C: acknowledgement that a slave of master parted from a channel
	MSG_PSYC_JOIN_REQUEST             MsgType = 687 // M->S->C: incoming join request from multicast
	MSG_PSYC_JOIN_DECISION            MsgType = 688 // C->S->M: decision about a join request
	MSG_PSYC_CHANNEL_MEMBERSHIP_STORE MsgType = 689 // C->S: request to add/remove channel slave in the membership database.
	MSG_PSYC_MESSAGE                  MsgType = 691 // S<--C: PSYC message which contains one or more message parts.
	MSG_PSYC_MESSAGE_HEADER           MsgType = 692 // M<->S<->C: PSYC message which contains a header and one or more message parts.
	MSG_PSYC_MESSAGE_METHOD           MsgType = 693 // Message part: method
	MSG_PSYC_MESSAGE_MODIFIER         MsgType = 694 // Message part: modifier
	MSG_PSYC_MESSAGE_MOD_CONT         MsgType = 695 // Message part: modifier continuation
	MSG_PSYC_MESSAGE_DATA             MsgType = 696 // Message part: data
	MSG_PSYC_MESSAGE_END              MsgType = 697 // Message part: end of message
	MSG_PSYC_MESSAGE_CANCEL           MsgType = 698 // Message part: message cancelled
	MSG_PSYC_MESSAGE_ACK              MsgType = 699 // S->C: message acknowledgement
	MSG_PSYC_HISTORY_REPLAY           MsgType = 701 // C->S: request channel history replay from PSYCstore.
	MSG_PSYC_HISTORY_RESULT           MsgType = 702 // S->C: result for a channel history request
	MSG_PSYC_STATE_GET                MsgType = 703 // C->S: request best matching state variable from PSYCstore.
	MSG_PSYC_STATE_GET_PREFIX         MsgType = 704 // C->S: request state variables with a given prefix from PSYCstore.
	MSG_PSYC_STATE_RESULT             MsgType = 705 // S->C: result for a state request.

	//------------------------------------------------------------------
	// CONVERSATION message types
	//------------------------------------------------------------------

	MSG_CONVERSATION_AUDIO               MsgType = 730 // Message to transmit the audio between helper and speaker/microphone library.
	MSG_CONVERSATION_CS_PHONE_REGISTER   MsgType = 731 // Client -> Server message to register a phone.
	MSG_CONVERSATION_CS_PHONE_PICK_UP    MsgType = 732 // Client -> Server message to reject/hangup a call
	MSG_CONVERSATION_CS_PHONE_HANG_UP    MsgType = 733 // Client -> Server message to reject/hangup a call
	MSG_CONVERSATION_CS_PHONE_CALL       MsgType = 734 // Client <- Server message to indicate a ringing phone
	MSG_CONVERSATION_CS_PHONE_RING       MsgType = 735 // Client <- Server message to indicate a ringing phone
	MSG_CONVERSATION_CS_PHONE_SUSPEND    MsgType = 736 // Client <-> Server message to suspend connection.
	MSG_CONVERSATION_CS_PHONE_RESUME     MsgType = 737 // Client <-> Server message to resume connection.
	MSG_CONVERSATION_CS_PHONE_PICKED_UP  MsgType = 738 // Service -> Client message to notify that phone was picked up.
	MSG_CONVERSATION_CS_AUDIO            MsgType = 739 // Client <-> Server message to send audio data.
	MSG_CONVERSATION_CADET_PHONE_RING    MsgType = 740 // Cadet: call initiation
	MSG_CONVERSATION_CADET_PHONE_HANG_UP MsgType = 741 // Cadet: hang up / refuse call
	MSG_CONVERSATION_CADET_PHONE_PICK_UP MsgType = 742 // Cadet: pick up phone (establish audio channel)
	MSG_CONVERSATION_CADET_PHONE_SUSPEND MsgType = 743 // Cadet: phone suspended.
	MSG_CONVERSATION_CADET_PHONE_RESUME  MsgType = 744 // Cadet: phone resumed.
	MSG_CONVERSATION_CADET_AUDIO         MsgType = 745 // Cadet: audio data

	//------------------------------------------------------------------
	// MULTICAST message types
	//------------------------------------------------------------------

	MSG_MULTICAST_ORIGIN_START        MsgType = 750 // C->S: Start the origin.
	MSG_MULTICAST_MEMBER_JOIN         MsgType = 751 // C->S: Join group as a member.
	MSG_MULTICAST_JOIN_REQUEST        MsgType = 752 // C<--S<->T: A peer wants to join the group. Unicast message to the origin or another group member.
	MSG_MULTICAST_JOIN_DECISION       MsgType = 753 // C<->S<->T: Response to a join request. Unicast message from a group member to the peer wanting to join.
	MSG_MULTICAST_PART_REQUEST        MsgType = 754 // A peer wants to part the group.
	MSG_MULTICAST_PART_ACK            MsgType = 755 // Acknowledgement sent in response to a part request. Unicast message from a group member to the peer wanting to part.
	MSG_MULTICAST_GROUP_END           MsgType = 756 // Group terminated.
	MSG_MULTICAST_MESSAGE             MsgType = 757 // C<->S<->T: Multicast message from the origin to all members.
	MSG_MULTICAST_REQUEST             MsgType = 758 // C<->S<->T: Unicast request from a group member to the origin.
	MSG_MULTICAST_FRAGMENT_ACK        MsgType = 759 // C->S: Acknowledgement of a message or request fragment for the client.
	MSG_MULTICAST_REPLAY_REQUEST      MsgType = 760 // C<->S<->T: Replay request from a group member to another member.
	MSG_MULTICAST_REPLAY_RESPONSE     MsgType = 761 // C<->S<->T: Replay response from a group member to another member.
	MSG_MULTICAST_REPLAY_RESPONSE_END MsgType = 762 // C<->S: End of replay response.

	//------------------------------------------------------------------
	// SECRETSHARING message types
	//------------------------------------------------------------------

	MSG_SECRETSHARING_CLIENT_GENERATE     MsgType = 780 // Establish a new session.
	MSG_SECRETSHARING_CLIENT_DECRYPT      MsgType = 781 // Request the decryption of a ciphertext.
	MSG_SECRETSHARING_CLIENT_DECRYPT_DONE MsgType = 782 // The service succeeded in decrypting a ciphertext.
	MSG_SECRETSHARING_CLIENT_SECRET_READY MsgType = 783 // Contains the peer's share.

	//------------------------------------------------------------------
	// PEERSTORE message types
	//------------------------------------------------------------------

	MSG_PEERSTORE_STORE          MsgType = 820 // Store request message
	MSG_PEERSTORE_ITERATE        MsgType = 821 // Iteration request
	MSG_PEERSTORE_ITERATE_RECORD MsgType = 822 // Iteration record message
	MSG_PEERSTORE_ITERATE_END    MsgType = 823 // Iteration end message
	MSG_PEERSTORE_WATCH          MsgType = 824 // Watch request
	MSG_PEERSTORE_WATCH_RECORD   MsgType = 825 // Watch response
	MSG_PEERSTORE_WATCH_CANCEL   MsgType = 826 // Watch cancel request

	//------------------------------------------------------------------
	// SOCIAL message types
	//------------------------------------------------------------------

	MSG_SOCIAL_RESULT_CODE         MsgType = 840 // S->C: result of an operation
	MSG_SOCIAL_HOST_ENTER          MsgType = 841 // C->S: request to enter a place as the host
	MSG_SOCIAL_HOST_ENTER_ACK      MsgType = 842 // S->C: host enter acknowledgement
	MSG_SOCIAL_GUEST_ENTER         MsgType = 843 // C->S: request to enter a place as a guest
	MSG_SOCIAL_GUEST_ENTER_BY_NAME MsgType = 844 // C->S: request to enter a place as a guest, using a GNS address
	MSG_SOCIAL_GUEST_ENTER_ACK     MsgType = 845 // S->C: guest enter acknowledgement
	MSG_SOCIAL_ENTRY_REQUEST       MsgType = 846 // P->S->C: incoming entry request from PSYC
	MSG_SOCIAL_ENTRY_DECISION      MsgType = 847 // C->S->P: decision about an entry request
	MSG_SOCIAL_PLACE_LEAVE         MsgType = 848 // C->S: request to leave a place
	MSG_SOCIAL_PLACE_LEAVE_ACK     MsgType = 849 // S->C: place leave acknowledgement
	MSG_SOCIAL_ZONE_ADD_PLACE      MsgType = 850 // C->S: add place to GNS zone
	MSG_SOCIAL_ZONE_ADD_NYM        MsgType = 851 // C->S: add nym to GNS zone
	MSG_SOCIAL_APP_CONNECT         MsgType = 852 // C->S: connect application
	MSG_SOCIAL_APP_DETACH          MsgType = 853 // C->S: detach a place from application
	MSG_SOCIAL_APP_EGO             MsgType = 854 // S->C: notify about an existing ego
	MSG_SOCIAL_APP_EGO_END         MsgType = 855 // S->C: end of ego list
	MSG_SOCIAL_APP_PLACE           MsgType = 856 // S->C: notify about an existing place
	MSG_SOCIAL_APP_PLACE_END       MsgType = 857 // S->C: end of place list
	MSG_SOCIAL_MSG_PROC_SET        MsgType = 858 // C->S: set message processing flags
	MSG_SOCIAL_MSG_PROC_CLEAR      MsgType = 859 // C->S: clear message processing flags

	//------------------------------------------------------------------
	// X-VINE DHT messages
	//------------------------------------------------------------------

	MSG_XDHT_P2P_TRAIL_SETUP                   MsgType = 880 // Trail setup request is received by a peer.
	MSG_XDHT_P2P_TRAIL_SETUP_RESULT            MsgType = 881 // Trail to a particular peer is returned to this peer.
	MSG_XDHT_P2P_VERIFY_SUCCESSOR              MsgType = 882 // Verify if your immediate successor is still your immediate successor.
	MSG_XDHT_P2P_NOTIFY_NEW_SUCCESSOR          MsgType = 883 // Notify your new immediate successor that you are its new predecessor.
	MSG_XDHT_P2P_VERIFY_SUCCESSOR_RESULT       MsgType = 884 // Message which contains the immediate predecessor of requested successor
	MSG_XDHT_P2P_GET_RESULT                    MsgType = 885 // Message which contains the get result.
	MSG_XDHT_P2P_TRAIL_SETUP_REJECTION         MsgType = 886 // Trail Rejection Message.
	MSG_XDHT_P2P_TRAIL_TEARDOWN                MsgType = 887 // Trail Tear down Message.
	MSG_XDHT_P2P_ADD_TRAIL                     MsgType = 888 // Routing table add message.
	MSG_XDHT_P2P_PUT                           MsgType = 890 // Peer is storing the data in DHT.
	MSG_XDHT_P2P_GET                           MsgType = 891 // Peer tries to find data in DHT.
	MSG_XDHT_P2P_NOTIFY_SUCCESSOR_CONFIRMATION MsgType = 892 // Send back peer that considers you are its successor.

	MSG_DHT_ACT_MALICIOUS           MsgType = 893 // Turn X-VINE DHT service malicious
	MSG_DHT_CLIENT_ACT_MALICIOUS_OK MsgType = 894 // Acknowledge receiving ACT MALICIOUS request

	//------------------------------------------------------------------
	// Whanau DHT messages
	//------------------------------------------------------------------

	MSG_WDHT_RANDOM_WALK          MsgType = 910 // This message contains the query for performing a random walk
	MSG_WDHT_RANDOM_WALK_RESPONSE MsgType = 911 // This message contains the result of a random walk
	MSG_WDHT_TRAIL_DESTROY        MsgType = 912 // This message contains a notification for the death of a trail
	MSG_WDHT_TRAIL_ROUTE          MsgType = 913 // This message are used to route a query to a peer
	MSG_WDHT_SUCCESSOR_FIND       MsgType = 914 // This message contains the query to transfer successor values.
	MSG_WDHT_GET                  MsgType = 915 // Message which contains the get query
	MSG_WDHT_PUT                  MsgType = 916 // Message which contains the "put", a response to #WDHT_SUCCESSOR_FIND.
	MSG_WDHT_GET_RESULT           MsgType = 917 // Message which contains the get result, a response to #WDHT_GET.

	//------------------------------------------------------------------
	// RPS messages
	//------------------------------------------------------------------

	MSG_RPS_PP_CHECK_LIVE   MsgType = 950 // RPS check liveliness message to check liveliness of other peer
	MSG_RPS_PP_PUSH         MsgType = 951 // RPS PUSH message to push own ID to another peer
	MSG_RPS_PP_PULL_REQUEST MsgType = 952 // RPS PULL REQUEST message to request the local view of another peer
	MSG_RPS_PP_PULL_REPLY   MsgType = 953 // RPS PULL REPLY message which contains the view of the other peer
	MSG_RPS_CS_SEED         MsgType = 954 // RPS CS SEED Message for the Client to seed peers into rps
	MSG_RPS_ACT_MALICIOUS   MsgType = 955 // Turn RPS service malicious
	MSG_RPS_CS_SUB_START    MsgType = 956 // RPS client-service message to start a sub sampler
	MSG_RPS_CS_SUB_STOP     MsgType = 957 // RPS client-service message to stop a sub sampler

	//------------------------------------------------------------------
	// RECLAIM messages
	//------------------------------------------------------------------

	MSG_RECLAIM_ATTRIBUTE_STORE           MsgType = 961
	MSG_RECLAIM_SUCCESS_RESPONSE          MsgType = 962
	MSG_RECLAIM_ATTRIBUTE_ITERATION_START MsgType = 963
	MSG_RECLAIM_ATTRIBUTE_ITERATION_STOP  MsgType = 964
	MSG_RECLAIM_ATTRIBUTE_ITERATION_NEXT  MsgType = 965
	MSG_RECLAIM_ATTRIBUTE_RESULT          MsgType = 966
	MSG_RECLAIM_ISSUE_TICKET              MsgType = 967
	MSG_RECLAIM_TICKET_RESULT             MsgType = 968
	MSG_RECLAIM_REVOKE_TICKET             MsgType = 969
	MSG_RECLAIM_REVOKE_TICKET_RESULT      MsgType = 970
	MSG_RECLAIM_CONSUME_TICKET            MsgType = 971
	MSG_RECLAIM_CONSUME_TICKET_RESULT     MsgType = 972
	MSG_RECLAIM_TICKET_ITERATION_START    MsgType = 973
	MSG_RECLAIM_TICKET_ITERATION_STOP     MsgType = 974
	MSG_RECLAIM_TICKET_ITERATION_NEXT     MsgType = 975
	MSG_RECLAIM_ATTRIBUTE_DELETE          MsgType = 976

	//------------------------------------------------------------------
	// CREDENTIAL messages
	//------------------------------------------------------------------

	MSG_CREDENTIAL_VERIFY         MsgType = 981 //
	MSG_CREDENTIAL_VERIFY_RESULT  MsgType = 982 //
	MSG_CREDENTIAL_COLLECT        MsgType = 983 //
	MSG_CREDENTIAL_COLLECT_RESULT MsgType = 984 //

	//------------------------------------------------------------------
	// CADET messages
	//------------------------------------------------------------------

	MSG_CADET_CONNECTION_CREATE                     MsgType = 1000 // Request the creation of a connection
	MSG_CADET_CONNECTION_CREATE_ACK                 MsgType = 1001 // Send origin an ACK that the connection is complete
	MSG_CADET_CONNECTION_BROKEN                     MsgType = 1002 // Notify that a connection is no longer valid
	MSG_CADET_CONNECTION_DESTROY                    MsgType = 1003 // Request the destuction of a connection
	MSG_CADET_CONNECTION_PATH_CHANGED_UNIMPLEMENTED MsgType = 1004 // At some point, the route will spontaneously change TODO
	MSG_CADET_CONNECTION_HOP_BY_HOP_ENCRYPTED_ACK   MsgType = 1005 // Hop-by-hop, connection dependent ACK. deprecated

	MSG_CADET_TUNNEL_ENCRYPTED_POLL MsgType = 1006 // We do not bother with ACKs for #CADET_TUNNEL_ENCRYPTED messages, but we instead poll for one if we got nothing for a while and start to be worried. deprecated
	MSG_CADET_TUNNEL_KX             MsgType = 1007 // Axolotl key exchange.
	MSG_CADET_TUNNEL_ENCRYPTED      MsgType = 1008 // Axolotl encrypted data.
	MSG_CADET_TUNNEL_KX_AUTH        MsgType = 1009 // Axolotl key exchange response with authentication.

	MSG_CADET_CHANNEL_APP_DATA             MsgType = 1010 // Payload data (inside an encrypted tunnel).
	MSG_CADET_CHANNEL_APP_DATA_ACK         MsgType = 1011 // Confirm payload data end-to-end.
	MSG_CADET_CHANNEL_KEEPALIVE            MsgType = 1012 // Announce connection is still alive (direction sensitive).
	MSG_CADET_CHANNEL_OPEN                 MsgType = 1013 // Ask the cadet service to create a new channel.
	MSG_CADET_CHANNEL_DESTROY              MsgType = 1014 // Ask the cadet service to destroy a channel.
	MSG_CADET_CHANNEL_OPEN_ACK             MsgType = 1015 // Confirm the creation of a channel
	MSG_CADET_CHANNEL_OPEN_NACK_DEPRECATED MsgType = 1016 // Reject the creation of a channel deprecated

	MSG_CADET_LOCAL_DATA            MsgType = 1020 // Payload client <-> service
	MSG_CADET_LOCAL_ACK             MsgType = 1021 // Local ACK for data.
	MSG_CADET_LOCAL_PORT_OPEN       MsgType = 1022 // Start listening on a port.
	MSG_CADET_LOCAL_PORT_CLOSE      MsgType = 1023 // Stop listening on a port.
	MSG_CADET_LOCAL_CHANNEL_CREATE  MsgType = 1024 // Ask the cadet service to create a new channel.
	MSG_CADET_LOCAL_CHANNEL_DESTROY MsgType = 1025 // Tell client that a channel was destroyed.

	MSG_CADET_LOCAL_REQUEST_INFO_CHANNEL MsgType = 1030 // Local information about all channels of service.
	MSG_CADET_LOCAL_INFO_CHANNEL         MsgType = 1031 // Local information of service about a specific channel.
	MSG_CADET_LOCAL_INFO_CHANNEL_END     MsgType = 1032 // End of local information of service about channels.
	MSG_CADET_LOCAL_REQUEST_INFO_PEERS   MsgType = 1033 // Request local information about all peers known to the service.
	MSG_CADET_LOCAL_INFO_PEERS           MsgType = 1034 // Local information about all peers known to the service.
	MSG_CADET_LOCAL_INFO_PEERS_END       MsgType = 1035 // End of local information about all peers known to the service.
	MSG_CADET_LOCAL_REQUEST_INFO_PATH    MsgType = 1036 // Request local information of service about paths to specific peer.
	MSG_CADET_LOCAL_INFO_PATH            MsgType = 1037 // Local information of service about a specific path.
	MSG_CADET_LOCAL_INFO_PATH_END        MsgType = 1038 // End of local information of service about a specific path.
	MSG_CADET_LOCAL_REQUEST_INFO_TUNNELS MsgType = 1039 // Request local information about all tunnels of service.
	MSG_CADET_LOCAL_INFO_TUNNELS         MsgType = 1040 // Local information about all tunnels of service.
	MSG_CADET_LOCAL_INFO_TUNNELS_END     MsgType = 1041 // End of local information about all tunnels of service.

	MSG_CADET_CLI MsgType = 1059 // Traffic (net-cat style) used by the Command Line Interface.

	//------------------------------------------------------------------
	// NAT messages
	//------------------------------------------------------------------

	MSG_NAT_REGISTER                      MsgType = 1060 // Message to ask NAT service to register a client.
	MSG_NAT_HANDLE_STUN                   MsgType = 1061 // Message to ask NAT service to handle a STUN packet.
	MSG_NAT_REQUEST_CONNECTION_REVERSAL   MsgType = 1062 // Message to ask NAT service to request connection reversal.
	MSG_NAT_CONNECTION_REVERSAL_REQUESTED MsgType = 1063 // Message to from NAT service notifying us that connection reversal was requested by another peer.
	MSG_NAT_ADDRESS_CHANGE                MsgType = 1064 // Message to from NAT service notifying us that one of our addresses changed.
	MSG_NAT_AUTO_REQUEST_CFG              MsgType = 1066 // Message to ask NAT service to request autoconfiguration.
	MSG_NAT_AUTO_CFG_RESULT               MsgType = 1065 // Message from NAT service with the autoconfiguration result.

	//------------------------------------------------------------------
	// AUCTION messages
	//------------------------------------------------------------------

	MSG_AUCTION_CLIENT_CREATE  MsgType = 1110 // Client wants to create a new auction.
	MSG_AUCTION_CLIENT_JOIN    MsgType = 1111 // Client wants to join an existing auction.
	MSG_AUCTION_CLIENT_OUTCOME MsgType = 1112 // Service reports the auction outcome to the client.

	//------------------------------------------------------------------
	// RPS_DEBUG messages
	//------------------------------------------------------------------

	MSG_RPS_CS_DEBUG_VIEW_REQUEST   MsgType = 1130 // Request updates of the view
	MSG_RPS_CS_DEBUG_VIEW_REPLY     MsgType = 1131 // Send update of the view
	MSG_RPS_CS_DEBUG_VIEW_CANCEL    MsgType = 1132 // Cancel getting updates of the view
	MSG_RPS_CS_DEBUG_STREAM_REQUEST MsgType = 1133 // Request biased input stream
	MSG_RPS_CS_DEBUG_STREAM_REPLY   MsgType = 1134 // Send peer of biased stream
	MSG_RPS_CS_DEBUG_STREAM_CANCEL  MsgType = 1135 // Cancel getting biased stream

	//------------------------------------------------------------------
	// CATCH-ALL_DEBUG message
	//------------------------------------------------------------------

	MSG_ALL MsgType = 65535 // Type used to match 'all' message types.
)
