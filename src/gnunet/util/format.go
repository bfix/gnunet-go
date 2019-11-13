package util

import (
	"fmt"
)

var scale = " kMGTPEO"

// Scale1024 returns an integer value (e.g. a size) as a human-readable
// string with scales: a size of 183467245 would result in "174,967M"
func Scale1024(n uint64) string {
	v := float64(n)
	var i int
	for i = 0; v > 1024; i++ {
		v /= 1024
	}
	if i == 0 {
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%.3f%c", v, scale[i])
}
