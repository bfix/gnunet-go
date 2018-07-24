package util

import (
	"time"
)

func GetAbsoluteTimeNow() uint64 {
	return getTimestamp(time.Now())
}

func GetAbsoluteTimeOffset(t time.Duration) uint64 {
	return getTimestamp(time.Now().Add(t))
}

func getTimestamp(t time.Time) uint64 {
	secs := t.Unix()
	usecs := t.Nanosecond() / 1000
	return uint64(secs*1000000) + uint64(usecs)
}
