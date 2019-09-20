package util

import (
	"math"
	"time"
)

//----------------------------------------------------------------------
// Absolute time
//----------------------------------------------------------------------

type AbsoluteTime struct {
	Val uint64 `order:"big"`
}

func NewAbsoluteTime(t time.Time) AbsoluteTime {
	secs := t.Unix()
	usecs := t.Nanosecond() / 1000
	return AbsoluteTime{
		Val: uint64(secs*1000000) + uint64(usecs),
	}
}

func AbsoluteTimeNow() AbsoluteTime {
	return NewAbsoluteTime(time.Now())
}

func (t AbsoluteTime) String() string {
	if t.Val == math.MaxUint64 {
		return "Never"
	}
	ts := time.Unix(int64(t.Val/(1000*1000)), int64((t.Val%1000)*1000))
	return ts.Format(time.RFC3339Nano)
}

func (t AbsoluteTime) Add(d time.Duration) AbsoluteTime {
	return AbsoluteTime{
		Val: t.Val + uint64(d.Milliseconds()),
	}
}

func (t AbsoluteTime) Expired() bool {
	// check for "never"
	if t.Val == math.MaxUint64 {
		return false
	}
	return t.Val < uint64(time.Now().Unix())
}

//----------------------------------------------------------------------
// Relative time
//----------------------------------------------------------------------

type RelativeTime struct {
	Val uint64 `order:"big"`
}

func NewRelativeTime(d time.Duration) RelativeTime {
	return RelativeTime{
		Val: uint64(d.Milliseconds()),
	}
}

func (t RelativeTime) String() string {
	if t.Val == math.MaxUint64 {
		return "Forever"
	}
	return time.Duration(t.Val * 1000).String()
}
