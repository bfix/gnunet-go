package gns

import (
	"gnunet/enums"
)

//======================================================================
// List of resource records types (for GNS/DNS queries)
//======================================================================

// RRTypeList is a list of integers representing RR types.
type RRTypeList []int

// Initialize a new type list with given type values
func NewRRTypeList(args ...int) (res RRTypeList) {
	for _, val := range args {
		// if GNS_TYPE_ANY is encountered, it becomes the sole type
		if val == enums.GNS_TYPE_ANY {
			res = make(RRTypeList, 1)
			res[0] = val
			return
		}
		res = append(res, val)
	}
	return
}

// HasType returns true if the type is included in the list
func (tl RRTypeList) HasType(t int) bool {
	// return true if type is GNS_TYPE_ANY
	if tl[0] == enums.GNS_TYPE_ANY {
		return true
	}
	// check for type in list
	for _, val := range tl {
		if val == t {
			return true
		}
	}
	return false
}
