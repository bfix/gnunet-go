package util

import (
	"fmt"
)

// Error variables
var (
	ErrUtilArrayTooSmall = fmt.Errorf("Array to small")
)

//----------------------------------------------------------------------
// Byte array helpers
//----------------------------------------------------------------------

// Clone creates a new array of same content as the argument.
func Clone(d []byte) []byte {
	r := make([]byte, len(d))
	copy(r, d)
	return r
}

// Reverse the content of a byte array
func Reverse(b []byte) []byte {
	bl := len(b)
	r := make([]byte, bl)
	for i := 0; i < bl; i++ {
		r[bl-i-1] = b[i]
	}
	return r
}

// IsNull returns true if all bytes in an array are set to 0.
func IsNull(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// CopyBlock copies 'in' to 'out' so that 'out' is filled completely.
// - If 'in' is larger than 'out', it is left-truncated before copy
// - If 'in' is smaller than 'out', it is left-padded with 0 before copy
func CopyBlock(out, in []byte) {
	count := len(in)
	size := len(out)
	from, to := 0, 0
	if count > size {
		from = count - size
	} else if count < size {
		to = size - count
		for i := 0; i < to; i++ {
			out[i] = 0
		}
	}
	copy(out[to:], in[from:])
}

// Fill an array with a value
func Fill(b []byte, val byte) {
	for i := 0; i < len(b); i++ {
		b[i] = val
	}
}

//----------------------------------------------------------------------
// String list helpers
//----------------------------------------------------------------------

// Reverse StringList reverse an array of strings
func ReverseStringList(s []string) []string {
	sl := len(s)
	r := make([]string, sl)
	for i := 0; i < sl; i++ {
		r[sl-i-1] = s[i]
	}
	return r
}

// Convert a binary representation of a string list. Each string is '\0'-
// terminated. The whole byte array is parsed; if the final string is not
// terminated, it is skipped.
func StringList(b []byte) []string {
	res := make([]string, 0)
	str := ""
	for _, ch := range b {
		if ch == 0 {
			res = append(res, str)
			str = ""
			continue
		}
		str += string(ch)
	}
	return res
}
