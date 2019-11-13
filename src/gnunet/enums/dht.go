package enums

// DHT flags and settings
var (
	DHT_RO_NONE                   = 0  // Default.  Do nothing special.
	DHT_RO_DEMULTIPLEX_EVERYWHERE = 1  // Each peer along the way should look at 'enc'
	DHT_RO_RECORD_ROUTE           = 2  // keep track of the route that the message took in the P2P network.
	DHT_RO_FIND_PEER              = 3  // This is a 'FIND-PEER' request, so approximate results are fine.
	DHT_RO_BART                   = 4  // Possible message option for query key randomization.
	DHT_RO_LAST_HOP               = 16 // Flag given to monitors if this was the last hop for a GET/PUT.

	DHT_GNS_REPLICATION_LEVEL = 10
)

// DHT block types
var (
	BLOCK_TYPE_ANY            = 0  // Any type of block, used as a wildcard when searching.
	BLOCK_TYPE_FS_DBLOCK      = 1  // Data block (leaf) in the CHK tree.
	BLOCK_TYPE_FS_IBLOCK      = 2  // Inner block in the CHK tree.
	BLOCK_TYPE_FS_KBLOCK      = 3  // Legacy type, no longer in use.
	BLOCK_TYPE_FS_SBLOCK      = 4  // Legacy type, no longer in use.
	BLOCK_TYPE_FS_NBLOCK      = 5  // Legacy type, no longer in use.
	BLOCK_TYPE_FS_ONDEMAND    = 6  // Type of a block representing a block to be encoded on demand from disk.
	BLOCK_TYPE_DHT_HELLO      = 7  // Type of a block that contains a HELLO for a peer
	BLOCK_TYPE_TEST           = 8  // Block for testing.
	BLOCK_TYPE_FS_UBLOCK      = 9  // Type of a block representing any type of search result (universal).
	BLOCK_TYPE_DNS            = 10 // Block for storing DNS exit service advertisements.
	BLOCK_TYPE_GNS_NAMERECORD = 11 // Block for storing record data
	BLOCK_TYPE_REVOCATION     = 12 // Block type for a revocation message by which a key is revoked.

	BLOCK_TYPE_REGEX             = 22 // Block to store a cadet regex state
	BLOCK_TYPE_REGEX_ACCEPT      = 23 // Block to store a cadet regex accepting state
	BLOCK_TYPE_SET_TEST          = 24 // Block for testing set/consensus.
	BLOCK_TYPE_CONSENSUS_ELEMENT = 25 // Block type for consensus elements.
)
