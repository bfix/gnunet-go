package enums

var (
	GNS_MAX_BLOCK_SIZE = (63 * 1024) // Maximum size of a value that can be stored in a GNS block.

	// GNS record types
	GNS_TYPE_ANY                   = 0     // Record type indicating any record/'*'
	GNS_TYPE_PKEY                  = 65536 // Record type for GNS zone transfer ("PKEY").
	GNS_TYPE_NICK                  = 65537 // Record type for GNS nick names ("NICK").
	GNS_TYPE_LEHO                  = 65538 // Record type for GNS legacy hostnames ("LEHO").
	GNS_TYPE_VPN                   = 65539 // Record type for VPN resolution
	GNS_TYPE_GNS2DNS               = 65540 // Record type for delegation to DNS.
	GNS_TYPE_BOX                   = 65541 // Record type for a boxed record (see TLSA/SRV handling in GNS).
	GNS_TYPE_PLACE                 = 65542 // Record type for a social place.
	GNS_TYPE_PHONE                 = 65543 // Record type for a phone (of CONVERSATION).
	GNS_TYPE_RECLAIM_ATTR          = 65544 // Record type for identity attributes (of RECLAIM).
	GNS_TYPE_RECLAIM_TICKET        = 65545 // Record type for local ticket references
	GNS_TYPE_CREDENTIAL            = 65547 // Record type for credential
	GNS_TYPE_POLICY                = 65548 // Record type for policies
	GNS_TYPE_ATTRIBUTE             = 65549 // Record type for reverse lookups
	GNS_TYPE_RECLAIM_ATTR_REF      = 65550 // Record type for reclaim records
	GNS_TYPE_RECLAIM_MASTER        = 65551 // Record type for RECLAIM master
	GNS_TYPE_RECLAIM_OIDC_CLIENT   = 65552 // Record type for reclaim OIDC clients
	GNS_TYPE_RECLAIM_OIDC_REDIRECT = 65553 // Record type for reclaim OIDC redirect URIs

	// GNS_LocalOptions
	GNS_LO_DEFAULT      = 0 // Defaults, look in cache, then in DHT.
	GNS_LO_NO_DHT       = 1 // Never look in the DHT, keep request to local cache.
	GNS_LO_LOCAL_MASTER = 2 // For the rightmost label, only look in the cache.
)
