package util

import ()

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
