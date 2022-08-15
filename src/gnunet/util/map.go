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
	"math/rand"
	"sync"
)

//----------------------------------------------------------------------
// ID list of active map processes:
// An active process (wrapped in a 'Process()' and 'ProcessRange()'
// call) locks (and unlocks) map access only once around a process, so
// calls to map methods from within a process are safe (no lock/unlock
// required).
//----------------------------------------------------------------------

// PIDList is a thread-safe list of active process IDs
type PIDList struct {
	sync.RWMutex
	list map[int]struct{}
}

// NewPIDList creates a new PID list instance
func NewPIDList() *PIDList {
	return &PIDList{
		list: make(map[int]struct{}),
	}
}

// Add pid to list
func (pl *PIDList) Add(pid int) {
	pl.Lock()
	defer pl.Unlock()
	pl.list[pid] = struct{}{}
}

// Remove pid from list
func (pl *PIDList) Remove(pid int) {
	pl.Lock()
	defer pl.Unlock()
	delete(pl.list, pid)
}

// Contains returns true if 'pid' is a list element
func (pl *PIDList) Contains(pid int) bool {
	pl.RLock()
	defer pl.RUnlock()
	_, ok := pl.list[pid]
	return ok
}

//----------------------------------------------------------------------
// Thread-safe map implementation
//----------------------------------------------------------------------

// Map comparable keys to values of any type
type Map[K comparable, V any] struct {
	sync.RWMutex

	list      map[K]V
	inProcess *PIDList
}

// NewMap allocates a new mapping.
func NewMap[K comparable, V any]() *Map[K, V] {
	return &Map[K, V]{
		list:      make(map[K]V),
		inProcess: NewPIDList(),
	}
}

//----------------------------------------------------------------------

// Process a function in the locked map context. Calls
// to other map functions in 'f' will skip their locks.
func (m *Map[K, V]) Process(f func(pid int) error, readonly bool) error {
	// handle locking
	m.lock(readonly, 0)
	pid := NextID()
	m.inProcess.Add(pid)
	defer func() {
		m.inProcess.Remove(pid)
		m.unlock(readonly, 0)
	}()
	// function call in unlocked environment
	return f(pid)
}

// Process a ranged function in the locked map context. Calls
// to other map functions in 'f' will skip their locks.
func (m *Map[K, V]) ProcessRange(f func(key K, value V, pid int) error, readonly bool) error {
	// handle locking
	m.lock(readonly, 0)
	pid := NextID()
	m.inProcess.Add(pid)
	defer func() {
		m.inProcess.Remove(pid)
		m.unlock(readonly, 0)
	}()
	// range over map and call function.
	for key, value := range m.list {
		if err := f(key, value, pid); err != nil {
			return err
		}
	}
	return nil
}

//----------------------------------------------------------------------

// Size returns the number of entries in the map.
func (m *Map[K, V]) Size() int {
	return len(m.list)
}

// Put value into map under given key.
func (m *Map[K, V]) Put(key K, value V, pid int) {
	m.lock(false, pid)
	defer m.unlock(false, pid)
	m.list[key] = value
}

// Get value with iven key from map.
func (m *Map[K, V]) Get(key K, pid int) (value V, ok bool) {
	m.lock(true, pid)
	defer m.unlock(true, pid)
	value, ok = m.list[key]
	return
}

// GetRandom returns a random map entry.
func (m *Map[K, V]) GetRandom(pid int) (key K, value V, ok bool) {
	m.lock(true, pid)
	defer m.unlock(true, pid)

	ok = false
	if size := m.Size(); size > 0 {
		idx := rand.Intn(size) //nolint:gosec // good enough for selection
		for key, value = range m.list {
			if idx == 0 {
				ok = true
				return
			}
			idx--
		}
	}
	return
}

// Delete key/value pair from map.
func (m *Map[K, V]) Delete(key K, pid int) {
	m.lock(false, pid)
	defer m.unlock(false, pid)
	delete(m.list, key)
}

//----------------------------------------------------------------------

// lock with given mode (if not in processing function)
func (m *Map[K, V]) lock(readonly bool, pid int) {
	if !m.inProcess.Contains(pid) {
		if readonly {
			m.RLock()
		} else {
			m.Lock()
		}
	}
}

// lock with given mode (if not in processing function)
func (m *Map[K, V]) unlock(readonly bool, pid int) {
	if !m.inProcess.Contains(pid) {
		if readonly {
			m.RUnlock()
		} else {
			m.Unlock()
		}
	}
}
