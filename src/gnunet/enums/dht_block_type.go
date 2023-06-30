// Code generated by enum generator; DO NOT EDIT.

//nolint:stylecheck // allow non-camel-case for constants
package enums

type BlockType uint32

// DHT block types
const (
BLOCK_TYPE_ANY BlockType = 0 // Identifier for any block.
BLOCK_TYPE_FS_DBLOCK BlockType = 1 // Data block (leaf) in the CHK tree.
BLOCK_TYPE_FS_IBLOCK BlockType = 2 // Inner block in the CHK tree.
BLOCK_TYPE_FS_ONDEMAND BlockType = 6 // Type of a block representing a block to be encoded on demand from disk. Should never appear on the network directly.
BLOCK_TYPE_LEGACY_HELLO BlockType = 7 // Legacy type of a block that contains a HELLO for a peer.
BLOCK_TYPE_TEST BlockType = 8 // Block for testing.
BLOCK_TYPE_FS_UBLOCK BlockType = 9 // Type of a block representing any type of search result (universal).
BLOCK_TYPE_DNS BlockType = 10 // Block for storing DNS exit service advertisements.
BLOCK_TYPE_GNS_NAMERECORD BlockType = 11 // Block for storing GNS record data.
BLOCK_TYPE_REVOCATION BlockType = 12 // Block type for a revocation message by which a key is revoked.
BLOCK_TYPE_DHT_HELLO BlockType = 13 // Type of a block that contains a DHT-NG HELLO for a peer.
BLOCK_TYPE_REGEX BlockType = 22 // Block to store a cadet regex state
BLOCK_TYPE_REGEX_ACCEPT BlockType = 23 // Block to store a cadet regex accepting state
BLOCK_TYPE_SET_TEST BlockType = 24 // Block for testing set/consensus.  If first byte of the block is non-zero, the block is considered invalid.
BLOCK_TYPE_CONSENSUS_ELEMENT BlockType = 25 // Block type for consensus elements. Contains either special marker elements or a nested block.
BLOCK_TYPE_SETI_TEST BlockType = 26 // Block for testing set intersection.  If first byte of the block is non-zero, the block is considered invalid.
BLOCK_TYPE_SETU_TEST BlockType = 27 // Block for testing set union.  If first byte of the block is non-zero, the block is considered invalid.

)

