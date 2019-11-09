package util

import (
	"fmt"
)

var (
	ErrUtilArrayTooSmall = fmt.Errorf("Array to small")
)

func Clone(d []byte) []byte {
	r := make([]byte, len(d))
	copy(r, d)
	return r
}

func Reverse(b []byte) []byte {
	bl := len(b)
	r := make([]byte, bl)
	for i := 0; i < bl; i++ {
		r[bl-i-1] = b[i]
	}
	return r
}

func ReverseStrings(s []string) []string {
	sl := len(s)
	r := make([]string, sl)
	for i := 0; i < sl; i++ {
		r[sl-i-1] = s[i]
	}
	return r
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

func Fill(b []byte, val byte) {
	for i := 0; i < len(b); i++ {
		b[i] = val
	}
}
