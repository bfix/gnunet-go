package message

// GNUnet message types
const (
	TEST   = 1 // Test if service is online (deprecated)
	DUMMY  = 2 // Dummy messages for testing / benchmarking
	DUMMY2 = 3 // Another dummy messages for testing / benchmarking

	//------------------------------------------------------------------
	// RESOLVER message types
	//------------------------------------------------------------------

	RESOLVER_REQUEST  = 4 // Request DNS resolution
	RESOLVER_RESPONSE = 5 // Response to a DNS resolution request

	//------------------------------------------------------------------
	// AGPL source code download
	//------------------------------------------------------------------

	REQUEST_AGPL  = 6 // Message to request source code link
	RESPONSE_AGPL = 7 // Source code link

	//------------------------------------------------------------------
	// ARM message types
	//------------------------------------------------------------------

	ARM_START       = 8  // Request to ARM to start a service
	ARM_STOP        = 9  // Request to ARM to stop a service
	ARM_RESULT      = 10 // Response from ARM
	ARM_STATUS      = 11 // Status update from ARM
	ARM_LIST        = 12 // Request to ARM to list all currently running services
	ARM_LIST_RESULT = 13 // Response from ARM for listing currently running services
	ARM_MONITOR     = 14 // Request to ARM to notify client of service status changes
	ARM_TEST        = 15 // Test if ARM service is online

	//------------------------------------------------------------------
	// HELLO message types
	//------------------------------------------------------------------

	HELLO_LEGACY = 16 // Deprecated HELLO message
	HELLO        = 17 // HELLO message with friend_only flag

	//------------------------------------------------------------------
	// FRAGMENTATION message types
	//------------------------------------------------------------------

	FRAGMENT     = 18 // FRAGMENT of a larger message
	FRAGMENT_ACK = 19 // Acknowledgement of a FRAGMENT of a larger message

	//------------------------------------------------------------------
	// Transport-WLAN message types
	//------------------------------------------------------------------

	WLAN_DATA_TO_HELPER   = 39 // Type of data messages from the plugin to the gnunet-wlan-helper
	WLAN_DATA_FROM_HELPER = 40 // Type of data messages from the gnunet-wlan-helper to the plugin
	WLAN_HELPER_CONTROL   = 41 // Control message between the gnunet-wlan-helper and the daemon (with the MAC)
	WLAN_ADVERTISEMENT    = 42 // Type of messages for advertisement over wlan
	WLAN_DATA             = 43 // Type of messages for data over the wlan

	//------------------------------------------------------------------
	// Transport-DV message types
	//------------------------------------------------------------------

	DV_RECV              = 44 // DV service to DV Plugin message
	DV_SEND              = 45 // DV Plugin to DV service message
	DV_SEND_ACK          = 46 // Confirmation or failure of a DV_SEND message
	DV_ROUTE             = 47 // P2P DV message encapsulating some real message
	DV_START             = 48 // DV Plugin to DV service message, indicating startup.
	DV_CONNECT           = 49 // P2P DV message telling plugin that a peer connected
	DV_DISCONNECT        = 50 // P2P DV message telling plugin that a peer disconnected
	DV_SEND_NACK         = 51 // P2P DV message telling plugin that a message transmission failed (negative ACK)
	DV_DISTANCE_CHANGED  = 52 // P2P DV message telling plugin that our distance to a peer changed
	DV_BOX               = 53 // DV message box for boxing multiple messages.
	TRANSPORT_XU_MESSAGE = 55 // Experimental message type.

	//------------------------------------------------------------------
	// Transport-UDP message types
	//------------------------------------------------------------------

	TRANSPORT_UDP_MESSAGE = 56 // Normal UDP message type.
	TRANSPORT_UDP_ACK     = 57 // UDP ACK.

	//------------------------------------------------------------------
	// Transport-TCP message types
	//------------------------------------------------------------------

	TRANSPORT_TCP_NAT_PROBE = 60 // TCP NAT probe message
	TRANSPORT_TCP_WELCOME   = 61 // Welcome message between TCP transports.
	TRANSPORT_ATS           = 62 // Message to force transport to update bandwidth assignment (LEGACY)

	//------------------------------------------------------------------
	// NAT message types
	//------------------------------------------------------------------

	NAT_TEST = 63 // Message to ask NAT server to perform traversal test

	//------------------------------------------------------------------
	// CORE message types
	//------------------------------------------------------------------

	CORE_INIT                 = 64 // Initial setup message from core client to core.
	CORE_INIT_REPLY           = 65 // Response from core to core client to INIT message.
	CORE_NOTIFY_CONNECT       = 67 // Notify clients about new peer-to-peer connections (triggered after key exchange).
	CORE_NOTIFY_DISCONNECT    = 68 // Notify clients about peer disconnecting.
	CORE_NOTIFY_STATUS_CHANGE = 69 // Notify clients about peer status change.
	CORE_NOTIFY_INBOUND       = 70 // Notify clients about incoming P2P messages.
	CORE_NOTIFY_OUTBOUND      = 71 // Notify clients about outgoing P2P transmissions.
	CORE_SEND_REQUEST         = 74 // Request from client to transmit message.
	CORE_SEND_READY           = 75 // Confirmation from core that message can now be sent
	CORE_SEND                 = 76 // Client with message to transmit (after SEND_READY confirmation was received).
	CORE_MONITOR_PEERS        = 78 // Request for connection monitoring from CORE service.
	CORE_MONITOR_NOTIFY       = 79 // Reply for monitor by CORE service.
	CORE_ENCRYPTED_MESSAGE    = 82 // Encapsulation for an encrypted message between peers.
	CORE_PING                 = 83 // Check that other peer is alive (challenge).
	CORE_PONG                 = 84 // Confirmation that other peer is alive.
	CORE_HANGUP               = 85 // Request by the other peer to terminate the connection.
	CORE_COMPRESSED_TYPE_MAP  = 86 // gzip-compressed type map of the sender
	CORE_BINARY_TYPE_MAP      = 87 // uncompressed type map of the sender
	CORE_EPHEMERAL_KEY        = 88 // Session key exchange between peers.
	CORE_CONFIRM_TYPE_MAP     = 89 // Other peer confirms having received the type map

	//------------------------------------------------------------------
	// DATASTORE message types
	//------------------------------------------------------------------

	DATASTORE_RESERVE            = 92  // Message sent by datastore client on join.
	DATASTORE_RELEASE_RESERVE    = 93  // Message sent by datastore client on join.
	DATASTORE_STATUS             = 94  // Message sent by datastore to client informing about status processing a request (in response to RESERVE, RELEASE_RESERVE, PUT, UPDATE and REMOVE requests).
	DATASTORE_PUT                = 95  // Message sent by datastore client to store data.
	DATASTORE_GET                = 97  // Message sent by datastore client to get data.
	DATASTORE_GET_REPLICATION    = 98  // Message sent by datastore client to get random data.
	DATASTORE_GET_ZERO_ANONYMITY = 99  // Message sent by datastore client to get random data.
	DATASTORE_DATA               = 100 // Message sent by datastore to client providing requested data (in response to GET or GET_RANDOM request).
	DATASTORE_DATA_END           = 101 // Message sent by datastore to client signaling end of matching data. This message will also be sent for "GET_RANDOM", even though "GET_RANDOM" returns at most one data item.
	DATASTORE_REMOVE             = 102 // Message sent by datastore client to remove data.
	DATASTORE_DROP               = 103 // Message sent by datastore client to drop the database.
	DATASTORE_GET_KEY            = 104 // Message sent by datastore client to get data by key.

	//------------------------------------------------------------------
	// FS message types
	//------------------------------------------------------------------

	FS_REQUEST_LOC_SIGN      = 126 // Message sent by fs client to request LOC signature.
	FS_REQUEST_LOC_SIGNATURE = 127 // Reply sent by fs service with LOC signature.
	FS_INDEX_START           = 128 // Message sent by fs client to start indexing.
	FS_INDEX_START_OK        = 129 // Affirmative response to a request for start indexing.
	FS_INDEX_START_FAILED    = 130 // Response to a request for start indexing that refuses.
	FS_INDEX_LIST_GET        = 131 // Request from client for list of indexed files.
	FS_INDEX_LIST_ENTRY      = 132 // Reply to client with an indexed file name.
	FS_INDEX_LIST_END        = 133 // Reply to client indicating end of list.
	FS_UNINDEX               = 134 // Request from client to unindex a file.
	FS_UNINDEX_OK            = 135 // Reply to client indicating unindex receipt.
	FS_START_SEARCH          = 136 // Client asks FS service to start a (keyword) search.
	FS_GET                   = 137 // P2P request for content (one FS to another).
	FS_PUT                   = 138 // P2P response with content or active migration of content.  Also used between the service and clients (in response to #FS_START_SEARCH).
	FS_MIGRATION_STOP        = 139 // Peer asks us to stop migrating content towards it for a while.
	FS_CADET_QUERY           = 140 // P2P request for content (one FS to another via a cadet).
	FS_CADET_REPLY           = 141 // P2P answer for content (one FS to another via a cadet).

	//------------------------------------------------------------------
	// DHT message types
	//------------------------------------------------------------------

	DHT_CLIENT_PUT               = 142 // Client wants to store item in DHT.
	DHT_CLIENT_GET               = 143 // Client wants to lookup item in DHT.
	DHT_CLIENT_GET_STOP          = 144 // Client wants to stop search in DHT.
	DHT_CLIENT_RESULT            = 145 // Service returns result to client.
	DHT_P2P_PUT                  = 146 // Peer is storing data in DHT.
	DHT_P2P_GET                  = 147 // Peer tries to find data in DHT.
	DHT_P2P_RESULT               = 148 // Data is returned to peer from DHT.
	DHT_MONITOR_GET              = 149 // Receive information about transiting GETs
	DHT_MONITOR_GET_RESP         = 150 // Receive information about transiting GET responses
	DHT_MONITOR_PUT              = 151 // Receive information about transiting PUTs
	DHT_MONITOR_PUT_RESP         = 152 // Receive information about transiting PUT responses (TODO)
	DHT_MONITOR_START            = 153 // Request information about transiting messages
	DHT_MONITOR_STOP             = 154 // Stop information about transiting messages
	DHT_CLIENT_GET_RESULTS_KNOWN = 156 // Certain results are already known to the client, filter those.

	//------------------------------------------------------------------
	// HOSTLIST message types
	//------------------------------------------------------------------

	HOSTLIST_ADVERTISEMENT = 160 // Hostlist advertisement message

	//------------------------------------------------------------------
	// STATISTICS message types
	//------------------------------------------------------------------

	STATISTICS_SET                = 168 // Set a statistical value.
	STATISTICS_GET                = 169 // Get a statistical value(s).
	STATISTICS_VALUE              = 170 // Response to a STATISTICS_GET message (with value).
	STATISTICS_END                = 171 // Response to a STATISTICS_GET message (end of value stream).
	STATISTICS_WATCH              = 172 // Watch changes to a statistical value.  Message format is the same as for GET, except that the subsystem and entry name must be given.
	STATISTICS_WATCH_VALUE        = 173 // Changes to a watched value.
	STATISTICS_DISCONNECT         = 174 // Client is done sending service requests and will now disconnect.
	STATISTICS_DISCONNECT_CONFIRM = 175 // Service confirms disconnect and that it is done processing all requests from the client.

	//------------------------------------------------------------------
	// VPN message types
	//------------------------------------------------------------------

	VPN_HELPER                     = 185 // Type of messages between the gnunet-vpn-helper and the daemon
	VPN_ICMP_TO_SERVICE            = 190 // ICMP packet for a service.
	VPN_ICMP_TO_INTERNET           = 191 // ICMP packet for the Internet.
	VPN_ICMP_TO_VPN                = 192 // ICMP packet for the VPN
	VPN_DNS_TO_INTERNET            = 193 // DNS request for a DNS exit service.
	VPN_DNS_FROM_INTERNET          = 194 // DNS reply from a DNS exit service.
	VPN_TCP_TO_SERVICE_START       = 195 // TCP packet for a service.
	VPN_TCP_TO_INTERNET_START      = 196 // TCP packet for the Internet.
	VPN_TCP_DATA_TO_EXIT           = 197 // TCP packet of an established connection.
	VPN_TCP_DATA_TO_VPN            = 198 // TCP packet of an established connection.
	VPN_UDP_TO_SERVICE             = 199 // UDP packet for a service.
	VPN_UDP_TO_INTERNET            = 200 // UDP packet for the Internet.
	VPN_UDP_REPLY                  = 201 // UDP packet from a remote host
	VPN_CLIENT_REDIRECT_TO_IP      = 202 // Client asks VPN service to setup an IP to redirect traffic via an exit node to some global IP address.
	VPN_CLIENT_REDIRECT_TO_SERVICE = 203 // Client asks VPN service to setup an IP to redirect traffic to some peer offering a service.
	VPN_CLIENT_USE_IP              = 204 // VPN service responds to client with an IP to use for the requested redirection.

	//------------------------------------------------------------------
	// VPN-DNS message types
	//------------------------------------------------------------------

	DNS_CLIENT_INIT     = 211 // Initial message from client to DNS service for registration.
	DNS_CLIENT_REQUEST  = 212 // Type of messages between the gnunet-helper-dns and the service
	DNS_CLIENT_RESPONSE = 213 // Type of messages between the gnunet-helper-dns and the service
	DNS_HELPER          = 214 // Type of messages between the gnunet-helper-dns and the service

	//------------------------------------------------------------------
	// CHAT message types START
	//------------------------------------------------------------------

	CHAT_JOIN_REQUEST              = 300 // Message sent from client to join a chat room.
	CHAT_JOIN_NOTIFICATION         = 301 // Message sent to client to indicate joining of another room member.
	CHAT_LEAVE_NOTIFICATION        = 302 // Message sent to client to indicate leaving of another room member.
	CHAT_MESSAGE_NOTIFICATION      = 303 // Notification sent by service to client indicating that we've received a chat message.
	CHAT_TRANSMIT_REQUEST          = 304 // Request sent by client to transmit a chat message to another room members.
	CHAT_CONFIRMATION_RECEIPT      = 305 // Receipt sent from a message receiver to the service to confirm delivery of a chat message.
	CHAT_CONFIRMATION_NOTIFICATION = 306 // Notification sent from the service to the original sender to acknowledge delivery of a chat message.
	CHAT_P2P_JOIN_NOTIFICATION     = 307 // P2P message sent to indicate joining of another room member.
	CHAT_P2P_LEAVE_NOTIFICATION    = 308 // P2P message sent to indicate leaving of another room member.
	CHAT_P2P_SYNC_REQUEST          = 309 // P2P message sent to a newly connected peer to request its known clients in order to synchronize room members.
	CHAT_P2P_MESSAGE_NOTIFICATION  = 310 // Notification sent from one peer to another to indicate that we have received a chat message.
	CHAT_P2P_CONFIRMATION_RECEIPT  = 311 // P2P receipt confirming delivery of a chat message.

	//------------------------------------------------------------------
	// NSE (network size estimation) message types
	//------------------------------------------------------------------

	NSE_START     = 321 // client->service message indicating start
	NSE_P2P_FLOOD = 322 // P2P message sent from nearest peer
	NSE_ESTIMATE  = 323 // service->client message indicating

	//------------------------------------------------------------------
	// PEERINFO message types
	//------------------------------------------------------------------

	PEERINFO_GET      = 330 // Request update and listing of a peer
	PEERINFO_GET_ALL  = 331 // Request update and listing of all peers
	PEERINFO_INFO     = 332 // Information about one of the peers
	PEERINFO_INFO_END = 333 // End of information about other peers
	PEERINFO_NOTIFY   = 334 // Start notifying this client about changes

	//------------------------------------------------------------------
	// ATS message types
	//------------------------------------------------------------------

	ATS_START                  = 340 // Type of the 'struct ClientStartMessage' sent by clients to ATS to identify the type of the client.
	ATS_REQUEST_ADDRESS        = 341 // Type of the 'struct RequestAddressMessage' sent by clients to request an address to help connect.
	ATS_REQUEST_ADDRESS_CANCEL = 342 // Type of the 'struct RequestAddressMessage' sent by clients to request an address to help connect.
	ATS_ADDRESS_UPDATE         = 343 // Type of the 'struct AddressUpdateMessage' sent by clients to ATS to inform ATS about performance changes.
	ATS_ADDRESS_DESTROYED      = 344 // Type of the 'struct AddressDestroyedMessage' sent by clients to ATS  to inform ATS about an address being unavailable.
	ATS_ADDRESS_SUGGESTION     = 345 // Type of the 'struct AddressSuggestionMessage' sent by ATS to clients to suggest switching to a different address.
	ATS_PEER_INFORMATION       = 346 // Type of the 'struct PeerInformationMessage' sent by ATS to clients to inform about QoS for a particular connection.
	ATS_RESERVATION_REQUEST    = 347 // Type of the 'struct ReservationRequestMessage' sent by clients to ATS to ask for inbound bandwidth reservations.
	ATS_RESERVATION_RESULT     = 348 // Type of the 'struct ReservationResultMessage' sent by ATS to clients  in response to a reservation request.
	ATS_PREFERENCE_CHANGE      = 349 // Type of the 'struct ChangePreferenceMessage' sent by clients to ATS to ask for allocation preference changes.
	ATS_SESSION_RELEASE        = 350 // Type of the 'struct SessionReleaseMessage' sent by ATS to client to confirm that a session ID was destroyed.
	ATS_ADDRESS_ADD            = 353 // Type of the 'struct AddressUpdateMessage' sent by client to ATS to add a new address
	ATS_ADDRESSLIST_REQUEST    = 354 // Type of the 'struct AddressListRequestMessage' sent by client to ATS to request information about addresses
	ATS_ADDRESSLIST_RESPONSE   = 355 // Type of the 'struct AddressListResponseMessage' sent by ATS to client with information about addresses
	ATS_PREFERENCE_FEEDBACK    = 356 // Type of the 'struct ChangePreferenceMessage' sent by clients to ATS to ask for allocation preference changes.

	//------------------------------------------------------------------
	// TRANSPORT message types
	//------------------------------------------------------------------

	TRANSPORT_START                      = 360 // Message from the core saying that the transport server should start giving it messages. This should automatically trigger the transmission of a HELLO message.
	TRANSPORT_CONNECT                    = 361 // Message from TRANSPORT notifying about a client that connected to us.
	TRANSPORT_DISCONNECT                 = 362 // Message from TRANSPORT notifying about a client that disconnected from us.
	TRANSPORT_SEND                       = 363 // Request to TRANSPORT to transmit a message.
	TRANSPORT_SEND_OK                    = 364 // Confirmation from TRANSPORT that message for transmission has been queued (and that the next message to this peer can now be passed to the service).  Note that this confirmation does NOT imply that the message was fully transmitted.
	TRANSPORT_RECV                       = 365 // Message from TRANSPORT notifying about a message that was received.
	TRANSPORT_SET_QUOTA                  = 366 // Message telling transport to limit its receive rate.
	TRANSPORT_ADDRESS_TO_STRING          = 367 // Request to look addresses of peers in server.
	TRANSPORT_ADDRESS_TO_STRING_REPLY    = 368 // Response to the address lookup request.
	TRANSPORT_BLACKLIST_INIT             = 369 // Register a client that wants to do blacklisting.
	TRANSPORT_BLACKLIST_QUERY            = 370 // Query to a blacklisting client (is this peer blacklisted)?
	TRANSPORT_BLACKLIST_REPLY            = 371 // Reply from blacklisting client (answer to blacklist query).
	TRANSPORT_PING                       = 372 // Transport PING message
	TRANSPORT_PONG                       = 373 // Transport PONG message
	TRANSPORT_SESSION_SYN                = 375 // Transport SYN message exchanged between transport services to indicate that a session should be marked as 'connected'.
	TRANSPORT_SESSION_SYN_ACK            = 376 // Transport SYN_ACK message exchanged between transport services to indicate that a SYN message was accepted
	TRANSPORT_SESSION_ACK                = 377 // Transport ACK message exchanged between transport services to indicate that a SYN_ACK message was accepted
	TRANSPORT_SESSION_DISCONNECT         = 378 // Transport DISCONNECT message exchanged between transport services to indicate that a connection should be dropped.
	TRANSPORT_SESSION_QUOTA              = 379 // Message exchanged between transport services to indicate that the sender should limit its transmission rate to the indicated quota.
	TRANSPORT_MONITOR_PEER_REQUEST       = 380 // Request to monitor addresses used by a peer or all peers.
	TRANSPORT_SESSION_KEEPALIVE          = 381 // Message send by a peer to notify the other to keep the session alive and measure latency in a regular interval
	TRANSPORT_SESSION_KEEPALIVE_RESPONSE = 382 // Response to a #TRANSPORT_SESSION_KEEPALIVE message to measure latency in a regular interval
	TRANSPORT_MONITOR_PEER_RESPONSE      = 383 // Response to #TRANSPORT_MONITOR_PEER_REQUEST request to iterate over all known addresses.
	TRANSPORT_BROADCAST_BEACON           = 384 // Message send by a peer to notify the other to keep the session alive.
	TRANSPORT_TRAFFIC_METRIC             = 385 // Message containing traffic metrics for transport service
	TRANSPORT_MONITOR_PLUGIN_START       = 388 // Request to start monitoring the connection state of plugins.
	TRANSPORT_MONITOR_PLUGIN_EVENT       = 389 // Monitoring event about the connection state of plugins, generated in response to a subscription initiated via #TRANSPORT_MONITOR_PLUGIN_START
	TRANSPORT_MONITOR_PLUGIN_SYNC        = 390 // Monitoring event notifying client that the initial iteration is now completed and we are in sync with the state of the subsystem.
	TRANSPORT_MONITOR_PEER_RESPONSE_END  = 391 // terminating list of replies.

	//------------------------------------------------------------------
	// FS-PUBLISH-HELPER IPC Messages
	//------------------------------------------------------------------

	FS_PUBLISH_HELPER_PROGRESS_FILE      = 420 // Progress information from the helper: found a file
	FS_PUBLISH_HELPER_PROGRESS_DIRECTORY = 421 // Progress information from the helper: found a directory
	FS_PUBLISH_HELPER_ERROR              = 422 // Error signal from the helper.
	FS_PUBLISH_HELPER_SKIP_FILE          = 423 // Signal that helper skipped a file.
	FS_PUBLISH_HELPER_COUNTING_DONE      = 424 // Signal that helper is done scanning the directory tree.
	FS_PUBLISH_HELPER_META_DATA          = 425 // Extracted meta data from the helper.
	FS_PUBLISH_HELPER_FINISHED           = 426 // Signal that helper is done.

	//------------------------------------------------------------------
	// NAMECACHE message types
	//------------------------------------------------------------------

	NAMECACHE_LOOKUP_BLOCK          = 431 // Client to service: lookup block
	NAMECACHE_LOOKUP_BLOCK_RESPONSE = 432 // Service to client: result of block lookup
	NAMECACHE_BLOCK_CACHE           = 433 // Client to service: cache a block
	NAMECACHE_BLOCK_CACHE_RESPONSE  = 434 // Service to client: result of block cache request

	//------------------------------------------------------------------
	// NAMESTORE message types
	//------------------------------------------------------------------

	NAMESTORE_RECORD_STORE           = 435 // Client to service: store records (as authority)
	NAMESTORE_RECORD_STORE_RESPONSE  = 436 // Service to client: result of store operation.
	NAMESTORE_RECORD_LOOKUP          = 437 // Client to service: lookup label
	NAMESTORE_RECORD_LOOKUP_RESPONSE = 438 // Service to client: lookup label
	NAMESTORE_ZONE_TO_NAME           = 439 // Client to service: "reverse" lookup for zone name based on zone key
	NAMESTORE_ZONE_TO_NAME_RESPONSE  = 440 // Service to client: result of zone-to-name lookup.
	NAMESTORE_MONITOR_START          = 441 // Client to service: start monitoring (yields sequence of "ZONE_ITERATION_RESPONSES" --- forever).
	NAMESTORE_MONITOR_SYNC           = 442 // Service to client: you're now in sync.
	NAMESTORE_RECORD_RESULT          = 443 // Service to client: here is a (plaintext) record you requested.
	NAMESTORE_MONITOR_NEXT           = 444 // Client to service: I am now ready for the next (set of) monitor events. Monitoring equivlaent of #NAMESTORE_ZONE_ITERATION_NEXT.
	NAMESTORE_ZONE_ITERATION_START   = 445 // Client to service: please start iteration; receives "NAMESTORE_LOOKUP_NAME_RESPONSE" messages in return.
	NAMESTORE_ZONE_ITERATION_NEXT    = 447 // Client to service: next record(s) in iteration please.
	NAMESTORE_ZONE_ITERATION_STOP    = 448 // Client to service: stop iterating.

	//------------------------------------------------------------------
	// LOCKMANAGER message types
	//------------------------------------------------------------------

	LOCKMANAGER_ACQUIRE = 450 // Message to acquire Lock
	LOCKMANAGER_RELEASE = 451 // Message to release lock
	LOCKMANAGER_SUCCESS = 452 // SUCCESS reply from lockmanager

	//------------------------------------------------------------------
	// TESTBED message types
	//------------------------------------------------------------------

	TESTBED_INIT                      = 460 // Initial message from a client to a testing control service
	TESTBED_ADD_HOST                  = 461 // Message to add host
	TESTBED_ADD_HOST_SUCCESS          = 462 // Message to signal that a add host succeeded
	TESTBED_LINK_CONTROLLERS          = 463 // Message to link delegated controller to slave controller
	TESTBED_CREATE_PEER               = 464 // Message to create a peer at a host
	TESTBED_RECONFIGURE_PEER          = 465 // Message to reconfigure a peer
	TESTBED_START_PEER                = 466 // Message to start a peer at a host
	TESTBED_STOP_PEER                 = 467 // Message to stop a peer at a host
	TESTBED_DESTROY_PEER              = 468 // Message to destroy a peer
	TESTBED_CONFIGURE_UNDERLAY_LINK   = 469 // Configure underlay link message
	TESTBED_OVERLAY_CONNECT           = 470 // Message to connect peers in a overlay
	TESTBED_PEER_EVENT                = 471 // Message for peer events
	TESTBED_PEER_CONNECT_EVENT        = 472 // Message for peer connect events
	TESTBED_OPERATION_FAIL_EVENT      = 473 // Message for operation events
	TESTBED_CREATE_PEER_SUCCESS       = 474 // Message to signal successful peer creation
	TESTBED_GENERIC_OPERATION_SUCCESS = 475 // Message to signal a generic operation has been successful
	TESTBED_GET_PEER_INFORMATION      = 476 // Message to get a peer's information
	TESTBED_PEER_INFORMATION          = 477 // Message containing the peer's information
	TESTBED_REMOTE_OVERLAY_CONNECT    = 478 // Message to request a controller to make one of its peer to connect to another peer using the contained HELLO
	TESTBED_GET_SLAVE_CONFIGURATION   = 479 // Message to request configuration of a slave controller
	TESTBED_SLAVE_CONFIGURATION       = 480 // Message which contains the configuration of slave controller
	TESTBED_LINK_CONTROLLERS_RESULT   = 481 // Message to signal the result of #TESTBED_LINK_CONTROLLERS request
	TESTBED_SHUTDOWN_PEERS            = 482 // A controller receiving this message floods it to its directly-connected sub-controllers and then stops and destroys all peers
	TESTBED_MANAGE_PEER_SERVICE       = 483 // Message to start/stop a service of a peer
	TESTBED_BARRIER_INIT              = 484 // Message to initialise a barrier.  Messages of these type are flooded to all sub-controllers
	TESTBED_BARRIER_CANCEL            = 485 // Message to cancel a barrier.  This message is flooded to all sub-controllers
	TESTBED_BARRIER_STATUS            = 486 // Message for signalling status of a barrier
	TESTBED_BARRIER_WAIT              = 487 // Message sent by a peer when it has reached a barrier and is waiting for it to be crossed
	TESTBED_MAX                       = 488 // Not really a message, but for careful checks on the testbed messages; Should always be the maximum and never be used to send messages with this type
	TESTBED_HELPER_INIT               = 495 // The initialization message towards gnunet-testbed-helper
	TESTBED_HELPER_REPLY              = 496 // The reply message from gnunet-testbed-helper

	//------------------------------------------------------------------
	// GNS.
	//------------------------------------------------------------------

	GNS_LOOKUP                = 500 // Client would like to resolve a name.
	GNS_LOOKUP_RESULT         = 501 // Service response to name resolution request from client.
	GNS_REVERSE_LOOKUP        = 502 // Reverse lookup
	GNS_REVERSE_LOOKUP_RESULT = 503 // Response to reverse lookup

	//------------------------------------------------------------------
	// CONSENSUS message types
	//------------------------------------------------------------------

	CONSENSUS_CLIENT_JOIN             = 520 // Join a consensus session. Sent by client to service as first message.
	CONSENSUS_CLIENT_INSERT           = 521 // Insert an element. Sent by client to service.
	CONSENSUS_CLIENT_BEGIN            = 522 // Begin accepting new elements from other participants. Sent by client to service.
	CONSENSUS_CLIENT_RECEIVED_ELEMENT = 523 // Sent by service when a new element is added.
	CONSENSUS_CLIENT_CONCLUDE         = 524 // Sent by client to service in order to start the consensus conclusion.
	CONSENSUS_CLIENT_CONCLUDE_DONE    = 525 // Sent by service to client in order to signal a completed consensus conclusion. Last message sent in a consensus session.
	CONSENSUS_CLIENT_ACK              = 540 // Sent by client to service, telling whether a received element should be accepted and propagated further or not.
	CONSENSUS_P2P_DELTA_ESTIMATE      = 541 // Strata estimator.
	CONSENSUS_P2P_DIFFERENCE_DIGEST   = 542 // IBF containing all elements of a peer.
	CONSENSUS_P2P_ELEMENTS            = 543 // One or more elements that are sent from peer to peer.
	CONSENSUS_P2P_ELEMENTS_REQUEST    = 544 // Elements, and requests for further elements
	CONSENSUS_P2P_ELEMENTS_REPORT     = 545 // Elements that a peer reports to be missing at the remote peer.
	CONSENSUS_P2P_HELLO               = 546 // Initialization message for consensus p2p communication.
	CONSENSUS_P2P_SYNCED              = 547 // Report that the peer is synced with the partner after successfuly decoding the invertible bloom filter.
	CONSENSUS_P2P_FIN                 = 548 // Interaction os over, got synched and reported all elements
	CONSENSUS_P2P_ABORT               = 548 // Abort a round, don't send requested elements anymore
	CONSENSUS_P2P_ROUND_CONTEXT       = 547 // Abort a round, don't send requested elements anymore

	//------------------------------------------------------------------
	// SET message types
	//------------------------------------------------------------------

	SET_UNION_P2P_REQUEST_FULL        = 565 // Demand the whole element from the other peer, given only the hash code.
	SET_UNION_P2P_DEMAND              = 566 // Demand the whole element from the other peer, given only the hash code.
	SET_UNION_P2P_INQUIRY             = 567 // Tell the other peer to send us a list of hashes that match an IBF key.
	SET_UNION_P2P_OFFER               = 568 // Tell the other peer which hashes match a given IBF key.
	SET_REJECT                        = 569 // Reject a set request.
	SET_CANCEL                        = 570 // Cancel a set operation
	SET_ITER_ACK                      = 571 // Acknowledge result from iteration
	SET_RESULT                        = 572 // Create an empty set
	SET_ADD                           = 573 // Add element to set
	SET_REMOVE                        = 574 // Remove element from set
	SET_LISTEN                        = 575 // Listen for operation requests
	SET_ACCEPT                        = 576 // Accept a set request
	SET_EVALUATE                      = 577 // Evaluate a set operation
	SET_CONCLUDE                      = 578 // Start a set operation with the given set
	SET_REQUEST                       = 579 // Notify the client of a request from a remote peer
	SET_CREATE                        = 580 // Create a new local set
	SET_P2P_OPERATION_REQUEST         = 581 // Request a set operation from a remote peer.
	SET_UNION_P2P_SE                  = 582 // Strata estimator.
	SET_UNION_P2P_IBF                 = 583 // Invertible bloom filter.
	SET_P2P_ELEMENTS                  = 584 // Actual set elements.
	SET_P2P_ELEMENT_REQUESTS          = 585 // Requests for the elements with the given hashes.
	SET_UNION_P2P_DONE                = 586 // Set operation is done.
	SET_ITER_REQUEST                  = 587 // Start iteration over set elements.
	SET_ITER_ELEMENT                  = 588 // Element result for the iterating client.
	SET_ITER_DONE                     = 589 // Iteration end marker for the client.
	SET_UNION_P2P_SEC                 = 590 // Compressed strata estimator.
	SET_INTERSECTION_P2P_ELEMENT_INFO = 591 // Information about the element count for intersection
	SET_INTERSECTION_P2P_BF           = 592 // Bloom filter message for intersection exchange started by Bob.
	SET_INTERSECTION_P2P_DONE         = 593 // Intersection operation is done.
	SET_COPY_LAZY_PREPARE             = 594 // Ask the set service to prepare a copy of a set.
	SET_COPY_LAZY_RESPONSE            = 595 // Give the client an ID for connecting to the set's copy.
	SET_COPY_LAZY_CONNECT             = 596 // Sent by the client to the server to connect to an existing, lazily copied set.
	SET_UNION_P2P_FULL_DONE           = 597 // Request all missing elements from the other peer, based on their sets and the elements we previously sent with #SET_P2P_ELEMENTS.
	SET_UNION_P2P_FULL_ELEMENT        = 598 // Send a set element, not as response to a demand but because we're sending the full set.
	SET_UNION_P2P_OVER                = 599 // Request all missing elements from the other peer, based on their sets and the elements we previously sent with #SET_P2P_ELEMENTS.

	//------------------------------------------------------------------
	// TESTBED LOGGER message types
	//------------------------------------------------------------------

	TESTBED_LOGGER_MSG = 600 // Message for TESTBED LOGGER
	TESTBED_LOGGER_ACK = 601 // Message for TESTBED LOGGER acknowledgement

	REGEX_ANNOUNCE = 620 // Advertise regex capability.
	REGEX_SEARCH   = 621 // Search for peer with matching capability.
	REGEX_RESULT   = 622 // Result in response to regex search.

	//------------------------------------------------------------------
	// IDENTITY message types
	//------------------------------------------------------------------

	IDENTITY_START          = 624 // First message send from identity client to service (to subscribe to updates).
	IDENTITY_RESULT_CODE    = 625 // Generic response from identity service with success and/or error message.
	IDENTITY_UPDATE         = 626 // Update about identity status from service to clients.
	IDENTITY_GET_DEFAULT    = 627 // Client requests to know default identity for a subsystem.
	IDENTITY_SET_DEFAULT    = 628 // Client sets default identity; or service informs about default identity.
	IDENTITY_CREATE         = 629 // Create new identity (client->service).
	IDENTITY_RENAME         = 630 // Rename existing identity (client->service).
	IDENTITY_DELETE         = 631 // Delete identity (client->service).
	IDENTITY_LOOKUP         = 632
	IDENTITY_LOOKUP_BY_NAME = 633

	//------------------------------------------------------------------
	// REVOCATION message types
	//------------------------------------------------------------------

	REVOCATION_QUERY           = 636 // Client to service: was this key revoked?
	REVOCATION_QUERY_RESPONSE  = 637 // Service to client: answer if key was revoked!
	REVOCATION_REVOKE          = 638 // Client to service OR peer-to-peer: revoke this key!
	REVOCATION_REVOKE_RESPONSE = 639 // Service to client: revocation confirmed

	//------------------------------------------------------------------
	// SCALARPRODUCT message types
	//------------------------------------------------------------------

	SCALARPRODUCT_CLIENT_TO_ALICE            = 640 // Client -> Alice
	SCALARPRODUCT_CLIENT_TO_BOB              = 641 // Client -> Bob
	SCALARPRODUCT_CLIENT_MULTIPART_ALICE     = 642 // Client -> Alice multipart
	SCALARPRODUCT_CLIENT_MULTIPART_BOB       = 643 // Client -> Bob multipart
	SCALARPRODUCT_SESSION_INITIALIZATION     = 644 // Alice -> Bob session initialization
	SCALARPRODUCT_ALICE_CRYPTODATA           = 645 // Alice -> Bob SP crypto-data (after intersection)
	SCALARPRODUCT_BOB_CRYPTODATA             = 647 // Bob -> Alice SP crypto-data
	SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART   = 648 // Bob -> Alice SP crypto-data multipart
	SCALARPRODUCT_RESULT                     = 649 // Alice/Bob -> Client Result
	SCALARPRODUCT_ECC_SESSION_INITIALIZATION = 650 // Alice -> Bob ECC session initialization
	SCALARPRODUCT_ECC_ALICE_CRYPTODATA       = 651 // Alice -> Bob ECC crypto data
	SCALARPRODUCT_ECC_BOB_CRYPTODATA         = 652 // Bob -> Alice ECC crypto data

	//------------------------------------------------------------------
	// PSYCSTORE message types
	//------------------------------------------------------------------

	PSYCSTORE_MEMBERSHIP_STORE     = 660 // Store a membership event.
	PSYCSTORE_MEMBERSHIP_TEST      = 661 // Test for membership of a member at a particular point in time.
	PSYCSTORE_FRAGMENT_STORE       = 662 //
	PSYCSTORE_FRAGMENT_GET         = 663 //
	PSYCSTORE_MESSAGE_GET          = 664 //
	PSYCSTORE_MESSAGE_GET_FRAGMENT = 665 //
	PSYCSTORE_COUNTERS_GET         = 666 //
	PSYCSTORE_STATE_MODIFY         = 668 //
	PSYCSTORE_STATE_SYNC           = 669 //
	PSYCSTORE_STATE_RESET          = 670 //
	PSYCSTORE_STATE_HASH_UPDATE    = 671 //
	PSYCSTORE_STATE_GET            = 672 //
	PSYCSTORE_STATE_GET_PREFIX     = 673 //
	PSYCSTORE_RESULT_CODE          = 674 // Generic response from PSYCstore service with success and/or error message.
	PSYCSTORE_RESULT_FRAGMENT      = 675 //
	PSYCSTORE_RESULT_COUNTERS      = 676 //
	PSYCSTORE_RESULT_STATE         = 677 //

	//------------------------------------------------------------------
	// PSYC message types
	//------------------------------------------------------------------

	PSYC_RESULT_CODE              = 680 // S->C: result of an operation
	PSYC_MASTER_START             = 681 // C->S: request to start a channel as a master
	PSYC_MASTER_START_ACK         = 682 // S->C: master start acknowledgement
	PSYC_SLAVE_JOIN               = 683 // C->S: request to join a channel as a slave
	PSYC_SLAVE_JOIN_ACK           = 684 // S->C: slave join acknowledgement
	PSYC_PART_REQUEST             = 685 // C->S: request to part from a channel
	PSYC_PART_ACK                 = 686 // S->C: acknowledgement that a slave of master parted from a channel
	PSYC_JOIN_REQUEST             = 687 // M->S->C: incoming join request from multicast
	PSYC_JOIN_DECISION            = 688 // C->S->M: decision about a join request
	PSYC_CHANNEL_MEMBERSHIP_STORE = 689 // C->S: request to add/remove channel slave in the membership database.
	PSYC_MESSAGE                  = 691 // S<--C: PSYC message which contains one or more message parts.
	PSYC_MESSAGE_HEADER           = 692 // M<->S<->C: PSYC message which contains a header and one or more message parts.
	PSYC_MESSAGE_METHOD           = 693 // Message part: method
	PSYC_MESSAGE_MODIFIER         = 694 // Message part: modifier
	PSYC_MESSAGE_MOD_CONT         = 695 // Message part: modifier continuation
	PSYC_MESSAGE_DATA             = 696 // Message part: data
	PSYC_MESSAGE_END              = 697 // Message part: end of message
	PSYC_MESSAGE_CANCEL           = 698 // Message part: message cancelled
	PSYC_MESSAGE_ACK              = 699 // S->C: message acknowledgement
	PSYC_HISTORY_REPLAY           = 701 // C->S: request channel history replay from PSYCstore.
	PSYC_HISTORY_RESULT           = 702 // S->C: result for a channel history request
	PSYC_STATE_GET                = 703 // C->S: request best matching state variable from PSYCstore.
	PSYC_STATE_GET_PREFIX         = 704 // C->S: request state variables with a given prefix from PSYCstore.
	PSYC_STATE_RESULT             = 705 // S->C: result for a state request.

	//------------------------------------------------------------------
	// CONVERSATION message types
	//------------------------------------------------------------------

	CONVERSATION_AUDIO               = 730 // Message to transmit the audio between helper and speaker/microphone library.
	CONVERSATION_CS_PHONE_REGISTER   = 731 // Client -> Server message to register a phone.
	CONVERSATION_CS_PHONE_PICK_UP    = 732 // Client -> Server message to reject/hangup a call
	CONVERSATION_CS_PHONE_HANG_UP    = 733 // Client -> Server message to reject/hangup a call
	CONVERSATION_CS_PHONE_CALL       = 734 // Client <- Server message to indicate a ringing phone
	CONVERSATION_CS_PHONE_RING       = 735 // Client <- Server message to indicate a ringing phone
	CONVERSATION_CS_PHONE_SUSPEND    = 736 // Client <-> Server message to suspend connection.
	CONVERSATION_CS_PHONE_RESUME     = 737 // Client <-> Server message to resume connection.
	CONVERSATION_CS_PHONE_PICKED_UP  = 738 // Service -> Client message to notify that phone was picked up.
	CONVERSATION_CS_AUDIO            = 739 // Client <-> Server message to send audio data.
	CONVERSATION_CADET_PHONE_RING    = 740 // Cadet: call initiation
	CONVERSATION_CADET_PHONE_HANG_UP = 741 // Cadet: hang up / refuse call
	CONVERSATION_CADET_PHONE_PICK_UP = 742 // Cadet: pick up phone (establish audio channel)
	CONVERSATION_CADET_PHONE_SUSPEND = 743 // Cadet: phone suspended.
	CONVERSATION_CADET_PHONE_RESUME  = 744 // Cadet: phone resumed.
	CONVERSATION_CADET_AUDIO         = 745 // Cadet: audio data

	//------------------------------------------------------------------
	// MULTICAST message types
	//------------------------------------------------------------------

	MULTICAST_ORIGIN_START        = 750 // C->S: Start the origin.
	MULTICAST_MEMBER_JOIN         = 751 // C->S: Join group as a member.
	MULTICAST_JOIN_REQUEST        = 752 // C<--S<->T: A peer wants to join the group. Unicast message to the origin or another group member.
	MULTICAST_JOIN_DECISION       = 753 // C<->S<->T: Response to a join request. Unicast message from a group member to the peer wanting to join.
	MULTICAST_PART_REQUEST        = 754 // A peer wants to part the group.
	MULTICAST_PART_ACK            = 755 // Acknowledgement sent in response to a part request. Unicast message from a group member to the peer wanting to part.
	MULTICAST_GROUP_END           = 756 // Group terminated.
	MULTICAST_MESSAGE             = 757 // C<->S<->T: Multicast message from the origin to all members.
	MULTICAST_REQUEST             = 758 // C<->S<->T: Unicast request from a group member to the origin.
	MULTICAST_FRAGMENT_ACK        = 759 // C->S: Acknowledgement of a message or request fragment for the client.
	MULTICAST_REPLAY_REQUEST      = 760 // C<->S<->T: Replay request from a group member to another member.
	MULTICAST_REPLAY_RESPONSE     = 761 // C<->S<->T: Replay response from a group member to another member.
	MULTICAST_REPLAY_RESPONSE_END = 762 // C<->S: End of replay response.

	//------------------------------------------------------------------
	// SECRETSHARING message types
	//------------------------------------------------------------------

	SECRETSHARING_CLIENT_GENERATE     = 780 // Establish a new session.
	SECRETSHARING_CLIENT_DECRYPT      = 781 // Request the decryption of a ciphertext.
	SECRETSHARING_CLIENT_DECRYPT_DONE = 782 // The service succeeded in decrypting a ciphertext.
	SECRETSHARING_CLIENT_SECRET_READY = 783 // Contains the peer's share.

	//------------------------------------------------------------------
	// PEERSTORE message types
	//------------------------------------------------------------------

	PEERSTORE_STORE          = 820 // Store request message
	PEERSTORE_ITERATE        = 821 // Iteration request
	PEERSTORE_ITERATE_RECORD = 822 // Iteration record message
	PEERSTORE_ITERATE_END    = 823 // Iteration end message
	PEERSTORE_WATCH          = 824 // Watch request
	PEERSTORE_WATCH_RECORD   = 825 // Watch response
	PEERSTORE_WATCH_CANCEL   = 826 // Watch cancel request

	//------------------------------------------------------------------
	// SOCIAL message types
	//------------------------------------------------------------------

	SOCIAL_RESULT_CODE         = 840 // S->C: result of an operation
	SOCIAL_HOST_ENTER          = 841 // C->S: request to enter a place as the host
	SOCIAL_HOST_ENTER_ACK      = 842 // S->C: host enter acknowledgement
	SOCIAL_GUEST_ENTER         = 843 // C->S: request to enter a place as a guest
	SOCIAL_GUEST_ENTER_BY_NAME = 844 // C->S: request to enter a place as a guest, using a GNS address
	SOCIAL_GUEST_ENTER_ACK     = 845 // S->C: guest enter acknowledgement
	SOCIAL_ENTRY_REQUEST       = 846 // P->S->C: incoming entry request from PSYC
	SOCIAL_ENTRY_DECISION      = 847 // C->S->P: decision about an entry request
	SOCIAL_PLACE_LEAVE         = 848 // C->S: request to leave a place
	SOCIAL_PLACE_LEAVE_ACK     = 849 // S->C: place leave acknowledgement
	SOCIAL_ZONE_ADD_PLACE      = 850 // C->S: add place to GNS zone
	SOCIAL_ZONE_ADD_NYM        = 851 // C->S: add nym to GNS zone
	SOCIAL_APP_CONNECT         = 852 // C->S: connect application
	SOCIAL_APP_DETACH          = 853 // C->S: detach a place from application
	SOCIAL_APP_EGO             = 854 // S->C: notify about an existing ego
	SOCIAL_APP_EGO_END         = 855 // S->C: end of ego list
	SOCIAL_APP_PLACE           = 856 // S->C: notify about an existing place
	SOCIAL_APP_PLACE_END       = 857 // S->C: end of place list
	SOCIAL_MSG_PROC_SET        = 858 // C->S: set message processing flags
	SOCIAL_MSG_PROC_CLEAR      = 859 // C->S: clear message processing flags

	//------------------------------------------------------------------
	// X-VINE DHT messages
	//------------------------------------------------------------------

	XDHT_P2P_TRAIL_SETUP                   = 880 // Trail setup request is received by a peer.
	XDHT_P2P_TRAIL_SETUP_RESULT            = 881 // Trail to a particular peer is returned to this peer.
	XDHT_P2P_VERIFY_SUCCESSOR              = 882 // Verify if your immediate successor is still your immediate successor.
	XDHT_P2P_NOTIFY_NEW_SUCCESSOR          = 883 // Notify your new immediate successor that you are its new predecessor.
	XDHT_P2P_VERIFY_SUCCESSOR_RESULT       = 884 // Message which contains the immediate predecessor of requested successor
	XDHT_P2P_GET_RESULT                    = 885 // Message which contains the get result.
	XDHT_P2P_TRAIL_SETUP_REJECTION         = 886 // Trail Rejection Message.
	XDHT_P2P_TRAIL_TEARDOWN                = 887 // Trail Tear down Message.
	XDHT_P2P_ADD_TRAIL                     = 888 // Routing table add message.
	XDHT_P2P_PUT                           = 890 // Peer is storing the data in DHT.
	XDHT_P2P_GET                           = 891 // Peer tries to find data in DHT.
	XDHT_P2P_NOTIFY_SUCCESSOR_CONFIRMATION = 892 // Send back peer that considers you are its successor.

	DHT_ACT_MALICIOUS           = 893 // Turn X-VINE DHT service malicious
	DHT_CLIENT_ACT_MALICIOUS_OK = 894 // Acknowledge receiving ACT MALICIOUS request

	//------------------------------------------------------------------
	// Whanau DHT messages
	//------------------------------------------------------------------

	WDHT_RANDOM_WALK          = 910 // This message contains the query for performing a random walk
	WDHT_RANDOM_WALK_RESPONSE = 911 // This message contains the result of a random walk
	WDHT_TRAIL_DESTROY        = 912 // This message contains a notification for the death of a trail
	WDHT_TRAIL_ROUTE          = 913 // This message are used to route a query to a peer
	WDHT_SUCCESSOR_FIND       = 914 // This message contains the query to transfer successor values.
	WDHT_GET                  = 915 // Message which contains the get query
	WDHT_PUT                  = 916 // Message which contains the "put", a response to #WDHT_SUCCESSOR_FIND.
	WDHT_GET_RESULT           = 917 // Message which contains the get result, a response to #WDHT_GET.

	//------------------------------------------------------------------
	// RPS messages
	//------------------------------------------------------------------

	RPS_PP_CHECK_LIVE   = 950 // RPS check liveliness message to check liveliness of other peer
	RPS_PP_PUSH         = 951 // RPS PUSH message to push own ID to another peer
	RPS_PP_PULL_REQUEST = 952 // RPS PULL REQUEST message to request the local view of another peer
	RPS_PP_PULL_REPLY   = 953 // RPS PULL REPLY message which contains the view of the other peer
	RPS_CS_SEED         = 954 // RPS CS SEED Message for the Client to seed peers into rps
	RPS_ACT_MALICIOUS   = 955 // Turn RPS service malicious
	RPS_CS_SUB_START    = 956 // RPS client-service message to start a sub sampler
	RPS_CS_SUB_STOP     = 957 // RPS client-service message to stop a sub sampler

	//------------------------------------------------------------------
	// RECLAIM messages
	//------------------------------------------------------------------

	RECLAIM_ATTRIBUTE_STORE           = 961
	RECLAIM_SUCCESS_RESPONSE          = 962
	RECLAIM_ATTRIBUTE_ITERATION_START = 963
	RECLAIM_ATTRIBUTE_ITERATION_STOP  = 964
	RECLAIM_ATTRIBUTE_ITERATION_NEXT  = 965
	RECLAIM_ATTRIBUTE_RESULT          = 966
	RECLAIM_ISSUE_TICKET              = 967
	RECLAIM_TICKET_RESULT             = 968
	RECLAIM_REVOKE_TICKET             = 969
	RECLAIM_REVOKE_TICKET_RESULT      = 970
	RECLAIM_CONSUME_TICKET            = 971
	RECLAIM_CONSUME_TICKET_RESULT     = 972
	RECLAIM_TICKET_ITERATION_START    = 973
	RECLAIM_TICKET_ITERATION_STOP     = 974
	RECLAIM_TICKET_ITERATION_NEXT     = 975
	RECLAIM_ATTRIBUTE_DELETE          = 976

	//------------------------------------------------------------------
	// CREDENTIAL messages
	//------------------------------------------------------------------

	CREDENTIAL_VERIFY         = 981 //
	CREDENTIAL_VERIFY_RESULT  = 982 //
	CREDENTIAL_COLLECT        = 983 //
	CREDENTIAL_COLLECT_RESULT = 984 //

	//------------------------------------------------------------------
	// CADET messages
	//------------------------------------------------------------------

	CADET_CONNECTION_CREATE                     = 1000 // Request the creation of a connection
	CADET_CONNECTION_CREATE_ACK                 = 1001 // Send origin an ACK that the connection is complete
	CADET_CONNECTION_BROKEN                     = 1002 // Notify that a connection is no longer valid
	CADET_CONNECTION_DESTROY                    = 1003 // Request the destuction of a connection
	CADET_CONNECTION_PATH_CHANGED_UNIMPLEMENTED = 1004 // At some point, the route will spontaneously change TODO
	CADET_CONNECTION_HOP_BY_HOP_ENCRYPTED_ACK   = 1005 // Hop-by-hop, connection dependent ACK. deprecated

	CADET_TUNNEL_ENCRYPTED_POLL = 1006 // We do not bother with ACKs for #CADET_TUNNEL_ENCRYPTED messages, but we instead poll for one if we got nothing for a while and start to be worried. deprecated
	CADET_TUNNEL_KX             = 1007 // Axolotl key exchange.
	CADET_TUNNEL_ENCRYPTED      = 1008 // Axolotl encrypted data.
	CADET_TUNNEL_KX_AUTH        = 1009 // Axolotl key exchange response with authentication.

	CADET_CHANNEL_APP_DATA             = 1010 // Payload data (inside an encrypted tunnel).
	CADET_CHANNEL_APP_DATA_ACK         = 1011 // Confirm payload data end-to-end.
	CADET_CHANNEL_KEEPALIVE            = 1012 // Announce connection is still alive (direction sensitive).
	CADET_CHANNEL_OPEN                 = 1013 // Ask the cadet service to create a new channel.
	CADET_CHANNEL_DESTROY              = 1014 // Ask the cadet service to destroy a channel.
	CADET_CHANNEL_OPEN_ACK             = 1015 // Confirm the creation of a channel
	CADET_CHANNEL_OPEN_NACK_DEPRECATED = 1016 // Reject the creation of a channel deprecated

	CADET_LOCAL_DATA            = 1020 // Payload client <-> service
	CADET_LOCAL_ACK             = 1021 // Local ACK for data.
	CADET_LOCAL_PORT_OPEN       = 1022 // Start listening on a port.
	CADET_LOCAL_PORT_CLOSE      = 1023 // Stop listening on a port.
	CADET_LOCAL_CHANNEL_CREATE  = 1024 // Ask the cadet service to create a new channel.
	CADET_LOCAL_CHANNEL_DESTROY = 1025 // Tell client that a channel was destroyed.

	CADET_LOCAL_REQUEST_INFO_CHANNEL = 1030 // Local information about all channels of service.
	CADET_LOCAL_INFO_CHANNEL         = 1031 // Local information of service about a specific channel.
	CADET_LOCAL_INFO_CHANNEL_END     = 1032 // End of local information of service about channels.
	CADET_LOCAL_REQUEST_INFO_PEERS   = 1033 // Request local information about all peers known to the service.
	CADET_LOCAL_INFO_PEERS           = 1034 // Local information about all peers known to the service.
	CADET_LOCAL_INFO_PEERS_END       = 1035 // End of local information about all peers known to the service.
	CADET_LOCAL_REQUEST_INFO_PATH    = 1036 // Request local information of service about paths to specific peer.
	CADET_LOCAL_INFO_PATH            = 1037 // Local information of service about a specific path.
	CADET_LOCAL_INFO_PATH_END        = 1038 // End of local information of service about a specific path.
	CADET_LOCAL_REQUEST_INFO_TUNNELS = 1039 // Request local information about all tunnels of service.
	CADET_LOCAL_INFO_TUNNELS         = 1040 // Local information about all tunnels of service.
	CADET_LOCAL_INFO_TUNNELS_END     = 1041 // End of local information about all tunnels of service.

	CADET_CLI = 1059 // Traffic (net-cat style) used by the Command Line Interface.

	//------------------------------------------------------------------
	// NAT messages
	//------------------------------------------------------------------

	NAT_REGISTER                      = 1060 // Message to ask NAT service to register a client.
	NAT_HANDLE_STUN                   = 1061 // Message to ask NAT service to handle a STUN packet.
	NAT_REQUEST_CONNECTION_REVERSAL   = 1062 // Message to ask NAT service to request connection reversal.
	NAT_CONNECTION_REVERSAL_REQUESTED = 1063 // Message to from NAT service notifying us that connection reversal was requested by another peer.
	NAT_ADDRESS_CHANGE                = 1064 // Message to from NAT service notifying us that one of our addresses changed.
	NAT_AUTO_REQUEST_CFG              = 1066 // Message to ask NAT service to request autoconfiguration.
	NAT_AUTO_CFG_RESULT               = 1065 // Message from NAT service with the autoconfiguration result.

	//------------------------------------------------------------------
	// AUCTION messages
	//------------------------------------------------------------------

	AUCTION_CLIENT_CREATE  = 1110 // Client wants to create a new auction.
	AUCTION_CLIENT_JOIN    = 1111 // Client wants to join an existing auction.
	AUCTION_CLIENT_OUTCOME = 1112 // Service reports the auction outcome to the client.

	//------------------------------------------------------------------
	// RPS_DEBUG messages
	//------------------------------------------------------------------

	RPS_CS_DEBUG_VIEW_REQUEST   = 1130 // Request updates of the view
	RPS_CS_DEBUG_VIEW_REPLY     = 1131 // Send update of the view
	RPS_CS_DEBUG_VIEW_CANCEL    = 1132 // Cancel getting updates of the view
	RPS_CS_DEBUG_STREAM_REQUEST = 1133 // Request biased input stream
	RPS_CS_DEBUG_STREAM_REPLY   = 1134 // Send peer of biased stream
	RPS_CS_DEBUG_STREAM_CANCEL  = 1135 // Cancel getting biased stream

	//------------------------------------------------------------------
	// CATCH-ALL_DEBUG message
	//------------------------------------------------------------------

	ALL = 65535 // Type used to match 'all' message types.
)
