package util

import (
	"math"
	"time"
)

func GetAbsoluteTimeNow() uint64 {
	return getTimestamp(time.Now())
}

func GetAbsoluteTimeOffset(t time.Duration) uint64 {
	return getTimestamp(time.Now().Add(t))
}

func Expired(ts uint64) bool {
	// check for "never"
	if ts == math.MaxUint64 {
		return false
	}
	return ts < uint64(time.Now().Unix())
}

func getTimestamp(t time.Time) uint64 {
	secs := t.Unix()
	usecs := t.Nanosecond() / 1000
	return uint64(secs*1000000) + uint64(usecs)
}
