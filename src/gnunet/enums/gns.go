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

// GNS constants
var (
	GNS_MAX_BLOCK_SIZE = (63 * 1024) // Maximum size of a value that can be stored in a GNS block.

	// GNS record flags
	GNS_FLAG_PRIVATE = 2  // Record is not shared on the DHT
	GNS_FLAG_SUPPL   = 4  // Supplemental records (e.g. NICK) in a block
	GNS_FLAG_EXPREL  = 8  // Expire time in record is in relative time.
	GNS_FLAG_SHADOW  = 16 // Record is ignored if non-expired records of same type exist in block

	// GNS record types
	GNS_TYPE_ANY                    = 0     // Record type indicating any record/'*'
	GNS_TYPE_DNS_A                  = 1     // [RFC1035] IPv4 Address record
	GNS_TYPE_DNS_NS                 = 2     // [RFC1035] Name Server record
	GNS_TYPE_DNS_CNAME              = 5     // [RFC1035] Canonical Name record
	GNS_TYPE_DNS_SOA                = 6     // [RFC2308] Start Of [a zone of] Authority
	GNS_TYPE_DNS_PTR                = 12    // [RFC1035] Pointer record
	GNS_TYPE_DNS_MX                 = 15    // [RFC7505] Mail eXchange record
	GNS_TYPE_DNS_TXT                = 16    // [RFC1035] Text record
	GNS_TYPE_DNS_RP                 = 17    // [RFC1183] Responsible Person
	GNS_TYPE_DNS_AFSDB              = 18    // [RFC1183] AFS Database Record
	GNS_TYPE_DNS_SIG                = 24    // [RFC2535] Signature
	GNS_TYPE_DNS_KEY                = 25    // [RFC2930] Key record
	GNS_TYPE_DNS_AAAA               = 28    // [RFC3596] IPv6 Address record
	GNS_TYPE_DNS_LOC                = 29    // [RFC1876] Location record
	GNS_TYPE_DNS_SRV                = 33    // [RFC2782] Service locator
	GNS_TYPE_DNS_NAPTR              = 35    // [RFC3403] Naming Authority Pointer
	GNS_TYPE_DNS_KX                 = 36    // [RFC2230] Key eXchanger record
	GNS_TYPE_DNS_CERT               = 37    // [RFC4398] Certificate record
	GNS_TYPE_DNS_DNAME              = 39    // [RFC2672] Delegation Name
	GNS_TYPE_DNS_APL                = 42    // [RFC3123] Address Prefix List
	GNS_TYPE_DNS_DS                 = 43    // [RFC4034] Delegation Signer
	GNS_TYPE_DNS_SSHFP              = 44    // [RFC4255] SSH public key Fingerprint
	GNS_TYPE_DNS_IPSECKEY           = 45    // [RFC4025] IPsec Key
	GNS_TYPE_DNS_RRSIG              = 46    // [RFC4034] DNSSEC Signature
	GNS_TYPE_DNS_NSEC               = 47    // [RFC4034] Next-Secure record
	GNS_TYPE_DNS_DNSKEY             = 48    // [RFC4034] DNS Key record
	GNS_TYPE_DNS_DHCID              = 49    // [RFC4701] DHCP Identifier
	GNS_TYPE_DNS_NSEC3              = 50    // [RFC5155] NSEC record version 3 or NSEC hashed
	GNS_TYPE_DNS_NSEC3PARAM         = 51    // [RFC5155] NSEC3 Parameters
	GNS_TYPE_DNS_TLSA               = 52    // [RFC6698] TLSA certificate association
	GNS_TYPE_DNS_HIP                = 55    // [RFC5205] Host Identity Protocol
	GNS_TYPE_DNS_CDS                = 59    // [RFC7344] Child DS
	GNS_TYPE_DNS_CDNSKEY            = 60    // [RFC7344] Child DNSKEY
	GNS_TYPE_DNS_TKEY               = 249   // [RFC2930] Secret Key
	GNS_TYPE_DNS_TSIG               = 250   // [RFC2845] Transaction Signature
	GNS_TYPE_DNS_URI                = 256   // [RFC7553] Uniform Resource Identifier
	GNS_TYPE_DNS_CAA                = 257   // [RFC6844] Certification Authority Authorization
	GNS_TYPE_DNS_TA                 = 32768 // [–] DNSSEC Trust Authorities
	GNS_TYPE_DNS_DLV                = 32769 // [RFC4431] DNSSEC Lookaside Validation record
	GNS_TYPE_PKEY                   = 65536 // Record type for GNS zone transfer ("PKEY").
	GNS_TYPE_NICK                   = 65537 // Record type for GNS nick names ("NICK").
	GNS_TYPE_LEHO                   = 65538 // Record type for GNS legacy hostnames ("LEHO").
	GNS_TYPE_VPN                    = 65539 // Record type for VPN resolution
	GNS_TYPE_GNS2DNS                = 65540 // Record type for delegation to DNS.
	GNS_TYPE_BOX                    = 65541 // Record type for a boxed record (see TLSA/SRV handling in GNS).
	GNS_TYPE_PLACE                  = 65542 // Record type for a social place.
	GNS_TYPE_PHONE                  = 65543 // Record type for a phone (of CONVERSATION).
	GNS_TYPE_RECLAIM_ATTR           = 65544 // Record type for identity attributes (of RECLAIM).
	GNS_TYPE_RECLAIM_TICKET         = 65545 // Record type for local ticket references
	GNS_TYPE_CREDENTIAL             = 65547 // Record type for credential
	GNS_TYPE_POLICY                 = 65548 // Record type for policies
	GNS_TYPE_ATTRIBUTE              = 65549 // Record type for reverse lookups
	GNS_TYPE_RECLAIM_ATTR_REF       = 65550 // Record type for reclaim records
	GNS_TYPE_RECLAIM_MASTER         = 65551 // Record type for RECLAIM master
	GNS_TYPE_RECLAIM_OIDC_CLIENT    = 65552 // Record type for reclaim OIDC clients
	GNS_TYPE_RECLAIM_OIDC_REDIRECT  = 65553 // Record type for reclaim OIDC redirect URIs
	GNS_TYPE_EDKEY                  = 65556 // Record type for GNS zone transfer ("EDKEY").
	GNS_TYPE_ERIS_READ_CAPABILITY   = 65557 // Encoding for Robust Immutable Storage (ERIS) binary read capability
	GNS_TYPE_MESSENGER_ROOM_ENTRY   = 65558 // Record type to share an entry of a messenger room
	GNS_TYPE_TOMBSTONE              = 65559 // Record type to indicate a previously delete record (PRIVATE only)
	GNS_TYPE_MESSENGER_ROOM_DETAILS = 65560 // Record type to store details about a messenger room

	GNS_TYPE = map[int]string{
		GNS_TYPE_ANY:                    "GNS_TYPE_ANY",
		GNS_TYPE_ATTRIBUTE:              "GNS_TYPE_ATTRIBUTE",
		GNS_TYPE_BOX:                    "GNS_TYPE_BOX",
		GNS_TYPE_CREDENTIAL:             "GNS_TYPE_CREDENTIAL",
		GNS_TYPE_DNS_AAAA:               "GNS_TYPE_DNS_AAAA",
		GNS_TYPE_DNS_AFSDB:              "GNS_TYPE_DNS_AFSDB",
		GNS_TYPE_DNS_A:                  "GNS_TYPE_DNS_A",
		GNS_TYPE_DNS_APL:                "GNS_TYPE_DNS_APL",
		GNS_TYPE_DNS_CAA:                "GNS_TYPE_DNS_CAA",
		GNS_TYPE_DNS_CDNSKEY:            "GNS_TYPE_DNS_CDNSKEY",
		GNS_TYPE_DNS_CDS:                "GNS_TYPE_DNS_CDS",
		GNS_TYPE_DNS_CERT:               "GNS_TYPE_DNS_CERT",
		GNS_TYPE_DNS_CNAME:              "GNS_TYPE_DNS_CNAME",
		GNS_TYPE_DNS_DHCID:              "GNS_TYPE_DNS_DHCID",
		GNS_TYPE_DNS_DLV:                "GNS_TYPE_DNS_DLV",
		GNS_TYPE_DNS_DNAME:              "GNS_TYPE_DNS_DNAME",
		GNS_TYPE_DNS_DNSKEY:             "GNS_TYPE_DNS_DNSKEY",
		GNS_TYPE_DNS_DS:                 "GNS_TYPE_DNS_DS",
		GNS_TYPE_DNS_HIP:                "GNS_TYPE_DNS_HIP",
		GNS_TYPE_DNS_IPSECKEY:           "GNS_TYPE_DNS_IPSECKEY",
		GNS_TYPE_DNS_KEY:                "GNS_TYPE_DNS_KEY",
		GNS_TYPE_DNS_KX:                 "GNS_TYPE_DNS_KX",
		GNS_TYPE_DNS_LOC:                "GNS_TYPE_DNS_LOC",
		GNS_TYPE_DNS_MX:                 "GNS_TYPE_DNS_MX",
		GNS_TYPE_DNS_NAPTR:              "GNS_TYPE_DNS_NAPTR",
		GNS_TYPE_DNS_NSEC3:              "GNS_TYPE_DNS_NSEC3",
		GNS_TYPE_DNS_NSEC3PARAM:         "GNS_TYPE_DNS_NSEC3PARAM",
		GNS_TYPE_DNS_NSEC:               "GNS_TYPE_DNS_NSEC",
		GNS_TYPE_DNS_NS:                 "GNS_TYPE_DNS_NS",
		GNS_TYPE_DNS_PTR:                "GNS_TYPE_DNS_PTR",
		GNS_TYPE_DNS_RP:                 "GNS_TYPE_DNS_RP",
		GNS_TYPE_DNS_RRSIG:              "GNS_TYPE_DNS_RRSIG",
		GNS_TYPE_DNS_SIG:                "GNS_TYPE_DNS_SIG",
		GNS_TYPE_DNS_SOA:                "GNS_TYPE_DNS_SOA",
		GNS_TYPE_DNS_SRV:                "GNS_TYPE_DNS_SRV",
		GNS_TYPE_DNS_SSHFP:              "GNS_TYPE_DNS_SSHFP",
		GNS_TYPE_DNS_TA:                 "GNS_TYPE_DNS_TA",
		GNS_TYPE_DNS_TKEY:               "GNS_TYPE_DNS_TKEY",
		GNS_TYPE_DNS_TLSA:               "GNS_TYPE_DNS_TLSA",
		GNS_TYPE_DNS_TSIG:               "GNS_TYPE_DNS_TSIG",
		GNS_TYPE_DNS_TXT:                "GNS_TYPE_DNS_TXT",
		GNS_TYPE_DNS_URI:                "GNS_TYPE_DNS_URI",
		GNS_TYPE_EDKEY:                  "GNS_TYPE_EDKEY",
		GNS_TYPE_ERIS_READ_CAPABILITY:   "GNS_TYPE_ERIS_READ_CAPABILITY",
		GNS_TYPE_GNS2DNS:                "GNS_TYPE_GNS2DNS",
		GNS_TYPE_LEHO:                   "GNS_TYPE_LEHO",
		GNS_TYPE_MESSENGER_ROOM_DETAILS: "GNS_TYPE_MESSENGER_ROOM_DETAILS",
		GNS_TYPE_MESSENGER_ROOM_ENTRY:   "GNS_TYPE_MESSENGER_ROOM_ENTRY",
		GNS_TYPE_NICK:                   "GNS_TYPE_NICK",
		GNS_TYPE_PHONE:                  "GNS_TYPE_PHONE",
		GNS_TYPE_PKEY:                   "GNS_TYPE_PKEY",
		GNS_TYPE_PLACE:                  "GNS_TYPE_PLACE",
		GNS_TYPE_POLICY:                 "GNS_TYPE_POLICY",
		GNS_TYPE_RECLAIM_ATTR:           "GNS_TYPE_RECLAIM_ATTR",
		GNS_TYPE_RECLAIM_ATTR_REF:       "GNS_TYPE_RECLAIM_ATTR_REF",
		GNS_TYPE_RECLAIM_MASTER:         "GNS_TYPE_RECLAIM_MASTER",
		GNS_TYPE_RECLAIM_OIDC_CLIENT:    "GNS_TYPE_RECLAIM_OIDC_CLIENT",
		GNS_TYPE_RECLAIM_OIDC_REDIRECT:  "GNS_TYPE_RECLAIM_OIDC_REDIRECT",
		GNS_TYPE_RECLAIM_TICKET:         "GNS_TYPE_RECLAIM_TICKET",
		GNS_TYPE_TOMBSTONE:              "GNS_TYPE_TOMBSTONE",
		GNS_TYPE_VPN:                    "GNS_TYPE_VPN",
	}

	// GNS_LocalOptions
	GNS_LO_DEFAULT      = 0 // Defaults, look in cache, then in DHT.
	GNS_LO_NO_DHT       = 1 // Never look in the DHT, keep request to local cache.
	GNS_LO_LOCAL_MASTER = 2 // For the rightmost label, only look in the cache.
)
