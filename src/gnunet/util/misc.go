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
	"strings"
)

//----------------------------------------------------------------------
// Count occurence of multiple instance at the same time.
//----------------------------------------------------------------------

// Counter is a metric with single key
type Counter[T comparable] map[T]int

// Add one to themetric for a given key and return current value
func (cm Counter[T]) Add(i T) int {
	count, ok := cm[i]
	if !ok {
		count = 1
	} else {
		count++
	}
	cm[i] = count
	return count
}

// Num returns the metric for a given key
func (cm Counter[T]) Num(i T) int {
	count, ok := cm[i]
	if !ok {
		count = 0
	}
	return count
}

//----------------------------------------------------------------------
// Parameter set with string keys and variable value types
//----------------------------------------------------------------------

// ParameterSet with string keys and variable value types
type ParameterSet map[string]any

// Get a parameter value with given type 'V'
func GetParam[V any](params ParameterSet, key string) (i V, ok bool) {
	var v any
	if v, ok = params[key]; ok {
		if i, ok = v.(V); ok {
			return
		}
	}
	return
}

//----------------------------------------------------------------------
// additional helpers
//----------------------------------------------------------------------

// StripPathRight returns a dot-separated path without
// its last (right-most) element.
func StripPathRight(s string) string {
	if idx := strings.LastIndex(s, "."); idx != -1 {
		return s[:idx]
	}
	return s
}
