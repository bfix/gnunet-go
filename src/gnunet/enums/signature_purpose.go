// Code generated by enum generator; DO NOT EDIT.

//nolint:stylecheck // allow non-camel-case for constants
package enums

type SigPurpose uint32

// Signature purpose values
const (
SIG_TEST SigPurpose = 0 // Test signature, not valid for anything other than writing a test. (Note that the signature verification code will accept this value).
SIG_TRANSPORT_PONG_OWN SigPurpose = 1 // Signature for confirming that this peer uses a particular address.
SIG_TRANSPORT_DISCONNECT SigPurpose = 2 // Signature for confirming that this peer intends to disconnect.
SIG_REVOCATION SigPurpose = 3 // Signature for confirming a key revocation.
SIG_NAMESPACE_ADVERTISEMENT SigPurpose = 4 // Signature for a namespace/pseudonym advertisement (by the namespace owner).
SIG_PEER_PLACEMENT SigPurpose = 5 // Signature by which a peer affirms that it is providing a certain bit of content for use in LOCation URIs.
SIG_DHT_HOP SigPurpose = 6 // Signature by which a peer affirms that it forwarded a message in the DHT.
SIG_HELLO SigPurpose = 7 // Signature by which a peer affirms its address.
SIG_DNS_RECORD SigPurpose = 11 // Signature on a GNUNET_DNS_Advertisement.
SIG_CHAT_MESSAGE SigPurpose = 12 // Signature of a chat message.
SIG_CHAT_RECEIPT SigPurpose = 13 // Signature of confirmation receipt for a chat message.
SIG_NSE_SEND SigPurpose = 14 // Signature of a network size estimate message.
SIG_GNS_RECORD_SIGN SigPurpose = 15 // Signature of a gnunet naming system record block
SIG_SET_ECC_KEY SigPurpose = 16 // Purpose is to set a session key.
SIG_FS_UBLOCK SigPurpose = 17 // UBlock Signature, done using DSS, not ECC
SIG_REGEX_ACCEPT SigPurpose = 18 // Accept state in regex DFA.  Peer affirms that it offers the matching service.
SIG_CONVERSATION_RING SigPurpose = 20 // Signature of a conversation ring.
SIG_SECRETSHARING_DKG1 SigPurpose = 21 // Signature for the first round of distributed key generation.
SIG_SECRETSHARING_DKG2 SigPurpose = 22 // Signature for the second round of distributed key generation.
SIG_SECRETSHARING_DECRYPTION SigPurpose = 23 // Signature for the cooperative decryption.
SIG_RECLAIM_CODE_SIGN SigPurpose = 27 // Signature for a GNUid Ticket
SIG_DELEGATE SigPurpose = 28 // Signature for a GNUnet credential
SIG_TRANSPORT_ADDRESS SigPurpose = 29 // Signature by a peer affirming that this is one of its addresses for the given time period.
SIG_TRANSPORT_EPHEMERAL SigPurpose = 30 // Signature by a peer affirming that the given ephemeral key is currently in use by that peer's transport service.
SIG_COMMUNICATOR_TCP_HANDSHAKE SigPurpose = 31 // Signature used by TCP communicator handshake.
SIG_COMMUNICATOR_TCP_REKEY SigPurpose = 32 // Signature used by TCP communicator rekey.
SIG_COMMUNICATOR_UDP_HANDSHAKE SigPurpose = 33 // Signature used by UDP communicator handshake.
SIG_COMMUNICATOR_UDP_BROADCAST SigPurpose = 34 // Signature used by UDP broadcasts.
SIG_TRANSPORT_CHALLENGE SigPurpose = 35 // Signature by a peer affirming that it received a challenge (and stating how long it expects the address on which the challenge was received to remain valid).
SIG_TRANSPORT_DV_HOP SigPurpose = 36 // Signature by a peer affirming that it is on a DV path.
SIG_TRANSPORT_DV_INITIATOR SigPurpose = 37 // Signature by a peer affirming that it originated the DV path.
SIG_CADET_CONNECTION_INITIATOR SigPurpose = 38 // Signature by a peer that like to create a connection.
SIG_COMMUNICATOR_TCP_HANDSHAKE_ACK SigPurpose = 39 // Signature by a peer sending back the nonce received at initial handshake.

)
