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
	"sync"
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
// Thread-safe map implementation
//----------------------------------------------------------------------

// Map keys to values
type Map[K comparable, V any] struct {
	list      map[K]V
	mtx       sync.RWMutex
	inProcess bool
}

// NewMap allocates a new mapping.
func NewMap[K comparable, V any]() *Map[K, V] {
	return &Map[K, V]{
		list:      make(map[K]V),
		inProcess: false,
	}
}

// Process a function in the locked map context. Calls
// to other map functions in 'f' will use additional locks.
func (m *Map[K, V]) Process(f func() error) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.inProcess = true
	err := f()
	m.inProcess = false
	return err
}

// Put value into map under given key.
func (m *Map[K, V]) Put(key K, value V) {
	if !m.inProcess {
		m.mtx.Lock()
		defer m.mtx.Unlock()
	}
	m.list[key] = value
}

// Get value with iven key from map.
func (m *Map[K, V]) Get(key K) (value V, ok bool) {
	if !m.inProcess {
		m.mtx.RLock()
		defer m.mtx.RUnlock()
	}
	value, ok = m.list[key]
	return
}

// Delete key/value pair from map.
func (m *Map[K, V]) Delete(key K) {
	if !m.inProcess {
		m.mtx.Lock()
		defer m.mtx.Unlock()
	}
	delete(m.list, key)
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
