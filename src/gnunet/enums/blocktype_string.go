// Code generated by "stringer -type=BlockType dht_block_type.go"; DO NOT EDIT.

package enums

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[BLOCK_TYPE_ANY-0]
	_ = x[BLOCK_TYPE_FS_DBLOCK-1]
	_ = x[BLOCK_TYPE_FS_IBLOCK-2]
	_ = x[BLOCK_TYPE_FS_ONDEMAND-6]
	_ = x[BLOCK_TYPE_DHT_HELLO-7]
	_ = x[BLOCK_TYPE_TEST-8]
	_ = x[BLOCK_TYPE_FS_UBLOCK-9]
	_ = x[BLOCK_TYPE_DNS-10]
	_ = x[BLOCK_TYPE_GNS_NAMERECORD-11]
	_ = x[BLOCK_TYPE_REVOCATION-12]
	_ = x[BLOCK_TYPE_DHT_URL_HELLO-13]
	_ = x[BLOCK_TYPE_REGEX-22]
	_ = x[BLOCK_TYPE_REGEX_ACCEPT-23]
	_ = x[BLOCK_TYPE_SET_TEST-24]
	_ = x[BLOCK_TYPE_CONSENSUS_ELEMENT-25]
	_ = x[BLOCK_TYPE_SETI_TEST-26]
}

const (
	_BlockType_name_0 = "BLOCK_TYPE_ANYBLOCK_TYPE_FS_DBLOCKBLOCK_TYPE_FS_IBLOCK"
	_BlockType_name_1 = "BLOCK_TYPE_FS_ONDEMANDBLOCK_TYPE_DHT_HELLOBLOCK_TYPE_TESTBLOCK_TYPE_FS_UBLOCKBLOCK_TYPE_DNSBLOCK_TYPE_GNS_NAMERECORDBLOCK_TYPE_REVOCATIONBLOCK_TYPE_DHT_URL_HELLO"
	_BlockType_name_2 = "BLOCK_TYPE_REGEXBLOCK_TYPE_REGEX_ACCEPTBLOCK_TYPE_SET_TESTBLOCK_TYPE_CONSENSUS_ELEMENTBLOCK_TYPE_SETI_TEST"
)

var (
	_BlockType_index_0 = [...]uint8{0, 14, 34, 54}
	_BlockType_index_1 = [...]uint8{0, 22, 42, 57, 77, 91, 116, 137, 161}
	_BlockType_index_2 = [...]uint8{0, 16, 39, 58, 86, 106}
)

func (i BlockType) String() string {
	switch {
	case i <= 2:
		return _BlockType_name_0[_BlockType_index_0[i]:_BlockType_index_0[i+1]]
	case 6 <= i && i <= 13:
		i -= 6
		return _BlockType_name_1[_BlockType_index_1[i]:_BlockType_index_1[i+1]]
	case 22 <= i && i <= 26:
		i -= 22
		return _BlockType_name_2[_BlockType_index_2[i]:_BlockType_index_2[i+1]]
	default:
		return "BlockType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
