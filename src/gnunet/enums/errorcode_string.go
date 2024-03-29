// Code generated by "stringer -type=ErrorCode error_codes.go"; DO NOT EDIT.

package enums

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[EC_NONE-0]
	_ = x[EC_UNKNOWN-1]
	_ = x[EC_SERVICE_COMMUNICATION_FAILED-101]
	_ = x[EC_IDENTITY_NOT_FOUND-200]
	_ = x[EC_IDENTITY_NAME_CONFLICT-201]
	_ = x[EC_IDENTITY_INVALID-202]
	_ = x[EC_NAMESTORE_UNKNOWN-5000]
	_ = x[EC_NAMESTORE_ITERATION_FAILED-5001]
	_ = x[EC_NAMESTORE_ZONE_NOT_FOUND-5002]
	_ = x[EC_NAMESTORE_RECORD_NOT_FOUND-5003]
	_ = x[EC_NAMESTORE_RECORD_DELETE_FAILED-5004]
	_ = x[EC_NAMESTORE_ZONE_EMPTY-5005]
	_ = x[EC_NAMESTORE_LOOKUP_ERROR-5006]
	_ = x[EC_NAMESTORE_NO_RECORDS_GIVEN-5007]
	_ = x[EC_NAMESTORE_RECORD_DATA_INVALID-5008]
	_ = x[EC_NAMESTORE_NO_LABEL_GIVEN-5009]
	_ = x[EC_NAMESTORE_NO_RESULTS-5010]
	_ = x[EC_NAMESTORE_RECORD_EXISTS-5011]
	_ = x[EC_NAMESTORE_RECORD_TOO_BIG-5012]
	_ = x[EC_NAMESTORE_BACKEND_FAILED-5013]
	_ = x[EC_NAMESTORE_STORE_FAILED-5014]
	_ = x[EC_NAMESTORE_LABEL_INVALID-5015]
}

const (
	_ErrorCode_name_0 = "EC_NONEEC_UNKNOWN"
	_ErrorCode_name_1 = "EC_SERVICE_COMMUNICATION_FAILED"
	_ErrorCode_name_2 = "EC_IDENTITY_NOT_FOUNDEC_IDENTITY_NAME_CONFLICTEC_IDENTITY_INVALID"
	_ErrorCode_name_3 = "EC_NAMESTORE_UNKNOWNEC_NAMESTORE_ITERATION_FAILEDEC_NAMESTORE_ZONE_NOT_FOUNDEC_NAMESTORE_RECORD_NOT_FOUNDEC_NAMESTORE_RECORD_DELETE_FAILEDEC_NAMESTORE_ZONE_EMPTYEC_NAMESTORE_LOOKUP_ERROREC_NAMESTORE_NO_RECORDS_GIVENEC_NAMESTORE_RECORD_DATA_INVALIDEC_NAMESTORE_NO_LABEL_GIVENEC_NAMESTORE_NO_RESULTSEC_NAMESTORE_RECORD_EXISTSEC_NAMESTORE_RECORD_TOO_BIGEC_NAMESTORE_BACKEND_FAILEDEC_NAMESTORE_STORE_FAILEDEC_NAMESTORE_LABEL_INVALID"
)

var (
	_ErrorCode_index_0 = [...]uint8{0, 7, 17}
	_ErrorCode_index_2 = [...]uint8{0, 21, 46, 65}
	_ErrorCode_index_3 = [...]uint16{0, 20, 49, 76, 105, 138, 161, 186, 215, 247, 274, 297, 323, 350, 377, 402, 428}
)

func (i ErrorCode) String() string {
	switch {
	case 0 <= i && i <= 1:
		return _ErrorCode_name_0[_ErrorCode_index_0[i]:_ErrorCode_index_0[i+1]]
	case i == 101:
		return _ErrorCode_name_1
	case 200 <= i && i <= 202:
		i -= 200
		return _ErrorCode_name_2[_ErrorCode_index_2[i]:_ErrorCode_index_2[i+1]]
	case 5000 <= i && i <= 5015:
		i -= 5000
		return _ErrorCode_name_3[_ErrorCode_index_3[i]:_ErrorCode_index_3[i+1]]
	default:
		return "ErrorCode(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
