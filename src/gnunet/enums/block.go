package enums

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
