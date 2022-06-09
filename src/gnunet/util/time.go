// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2022 Bernd Fix  >Y<
//
// gnunet-go is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// gnunet-go is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL3.0-or-later

package util

import (
	"math"
	"time"
)

//----------------------------------------------------------------------
// Absolute time
//----------------------------------------------------------------------

// AbsoluteTime refers to a unique point in time.
// The value is the elapsed time in microseconds (Unix epoch), so no timestamp
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

// NewAbsoluteTimeEpoch set the point in time to the given time value
func NewAbsoluteTimeEpoch(secs uint64) AbsoluteTime {
	return AbsoluteTime{
		Val: uint64(secs * 1000000),
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

// Epoch returns the seconds since Unix epoch.
func (t AbsoluteTime) Epoch() uint64 {
	return t.Val / 1000000
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

// Elapsed time since 't'. Return 0 if 't' is in the future.
func (t AbsoluteTime) Elapsed() RelativeTime {
	dt, elapsed := t.Diff(AbsoluteTimeNow())
	if !elapsed {
		dt = NewRelativeTime(0)
	}
	return dt
}

// Diff returns the relative time between two absolute times;
// returns true if t2 is after t1.
func (t AbsoluteTime) Diff(t2 AbsoluteTime) (dt RelativeTime, elapsed bool) {
	var d uint64
	if t.Compare(t2) == 1 {
		d = t.Val - t2.Val
		elapsed = false
	} else {
		d = t2.Val - t.Val
		elapsed = true
	}
	dt = RelativeTime{d}
	return
}

// Expired returns true if the timestamp is in the past.
func (t AbsoluteTime) Expired() bool {
	// check for "never"
	if t.Val == math.MaxUint64 {
		return false
	}
	return t.Val < uint64(time.Now().Unix())
}

// Compare two times (-1 = (t < t2), 0 = (t == t2), 1 = (t > t2)
func (t AbsoluteTime) Compare(t2 AbsoluteTime) int {
	if t.Val == math.MaxUint64 {
		if t2.Val == math.MaxUint64 {
			return 0
		}
		return 1
	}
	if t2.Val == math.MaxUint64 {
		return -1
	}
	if t.Val < t2.Val {
		return -1
	} else if t.Val == t2.Val {
		return 0
	}
	return 1
}

//----------------------------------------------------------------------
// Relative time
//----------------------------------------------------------------------

// RelativeTime is a timestamp defined relative to the current time.
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

// Add two durations
func (t RelativeTime) Add(t2 RelativeTime) {
	t.Val += t2.Val
}

// Compare two durations
func (t RelativeTime) Compare(t2 RelativeTime) int {
	switch {
	case t.Val < t2.Val:
		return -1
	case t.Val > t2.Val:
		return 1
	}
	return 0
}
