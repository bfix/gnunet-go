package util

import (
	"math"
	"time"
)

//----------------------------------------------------------------------
// Absolute time
//----------------------------------------------------------------------

// AbsoluteTime refers to a unique point in time.
// The value is the elapsed time in milliseconds (Unix epoch), so no timestamp
// before January 1st, 1970 is possible (not a restriction for GNUnet).
type AbsoluteTime struct {
	Val uint64 `order:"big"`
}

// NewAbsoluteTime set the point in time to the given time value
func NewAbsoluteTime(t time.Time) AbsoluteTime {
	secs := t.Unix()
	usecs := t.Nanosecond() / 1000
	return AbsoluteTime{
		Val: uint64(secs*1000000) + uint64(usecs),
	}
}

// AbsoluteTimeNow returns the current point in time.
func AbsoluteTimeNow() AbsoluteTime {
	return NewAbsoluteTime(time.Now())
}

// AbsoluteTimeNever returns the time defined as "never"
func AbsoluteTimeNever() AbsoluteTime {
	return AbsoluteTime{math.MaxUint64}
}

// String returns a human-readable notation of an absolute time.
func (t AbsoluteTime) String() string {
	if t.Val == math.MaxUint64 {
		return "Never"
	}
	ts := time.Unix(int64(t.Val/(1000*1000)), int64((t.Val%1000)*1000))
	return ts.Format(time.RFC3339Nano)
}

// Add a duration to an absolute time yielding a new absolute time.
func (t AbsoluteTime) Add(d time.Duration) AbsoluteTime {
	return AbsoluteTime{
		Val: t.Val + uint64(d.Milliseconds()),
	}
}

// Expired returns true if the timestamp is in the past.
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

// Relative time is a timestamp defined relative to the current time.
// It actually is more like a duration than a time...
type RelativeTime struct {
	Val uint64 `order:"big"`
}

// NewRelativeTime is initialized with a given duration.
func NewRelativeTime(d time.Duration) RelativeTime {
	return RelativeTime{
		Val: uint64(d.Milliseconds()),
	}
}

// String returns a human-readble representation of a relative time (duration).
func (t RelativeTime) String() string {
	if t.Val == math.MaxUint64 {
		return "Forever"
	}
	return time.Duration(t.Val * 1000).String()
}
