package util

import (
	"math/big"
)

func ToBuffer(n *big.Int, buf []byte, size int) {
	d := n.Bytes()
	dLen := len(d)
	from, to := 0, 0
	if dLen > size {
		from = dLen - size
	} else if dLen < size {
		to = size - dLen
		for i := 0; i < to; i++ {
			buf[i] = 0
		}
	}
	copy(buf[to:], d[from:])
}
