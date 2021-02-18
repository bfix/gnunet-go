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
	"strings"
)

// CounterMap is a metric with single key
type CounterMap map[interface{}]int

// Add one to themetric for a given key and return current value
func (cm CounterMap) Add(i interface{}) int {
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
func (cm CounterMap) Num(i interface{}) int {
	count, ok := cm[i]
	if !ok {
		count = 0
	}
	return count
}

// StripPathRight returns a dot-separated path without
// its last (right-most) element.
func StripPathRight(s string) string {
	if idx := strings.LastIndex(s, "."); idx != -1 {
		return s[:idx]
	}
	return s
}
