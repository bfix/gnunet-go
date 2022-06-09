// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
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
	"fmt"
)

// Error variables
var (
	ErrUtilArrayTooSmall = fmt.Errorf("array to small")
)

//----------------------------------------------------------------------
// generic array helpers
//----------------------------------------------------------------------

// Clone creates a new array of same content as the argument.
func Clone[T []E, E any](d T) T {
	r := make(T, len(d))
	copy(r, d)
	return r
}

// Equals returns true if two arrays match.
func Equals[T []E, E comparable](a, b T) bool {
	if len(a) != len(b) {
		return false
	}
	for i, e := range a {
		if e != b[i] {
			return false
		}
	}
	return true
}

// Reverse the content of an array
func Reverse[T []E, E any](b T) T {
	bl := len(b)
	r := make(T, bl)
	for i := 0; i < bl; i++ {
		r[bl-i-1] = b[i]
	}
	return r
}

// IsAll returns true if all elements in an array are set to null.
func IsAll[T []E, E comparable](b T, null E) bool {
	for _, v := range b {
		if v != null {
			return false
		}
	}
	return true
}

// Fill an array with a value
func Fill[T []E, E any](b T, val E) {
	for i := range b {
		b[i] = val
	}
}

//----------------------------------------------------------------------
// byte array helpers
//----------------------------------------------------------------------

// CopyAlignedBlock copies 'in' to 'out' so that 'out' is filled completely.
// - If 'in' is larger than 'out', it is left-truncated before copy
// - If 'in' is smaller than 'out', it is left-padded with 0 before copy
func CopyAlignedBlock(out, in []byte) {
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

//----------------------------------------------------------------------
// String list helpers
//----------------------------------------------------------------------

// StringList converts a binary representation of a string list. Each string
// is '\0'-terminated. The whole byte array is parsed; if the final string is
// not terminated, it is skipped.
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

// ReadCString reads a \0-terminate string from a buffer starting at the
// specified position. Returns the string and the new position (-1 for end
// of buffer reached)
func ReadCString(buf []byte, pos int) (string, int) {
	for idx := pos; idx < len(buf); idx++ {
		if buf[idx] == 0 {
			return string(buf[pos:idx]), idx + 1
		}
	}
	return "", -1
}
