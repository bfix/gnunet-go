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

package blocks

import (
	"bytes"
	"testing"
)

// Test parameter handling for queries
func TestQueryParams(t *testing.T) {
	q := NewGenericQuery(nil)

	// set parameters
	var (
		btype uint16 = DHT_BLOCK_ANY
		flags uint32 = 0
		name  string = "Test"
		data         = make([]byte, 8)
	)
	q.Set("btype", btype)
	q.Set("flags", flags)
	q.Set("name", name)
	q.Set("data", data)

	// get parameters
	var (
		t_btype uint16
		t_flags uint32
		t_name  string
		t_data  []byte
	)
	q.Get("btype", &t_btype)
	q.Get("flags", &t_flags)
	q.Get("name", &t_name)
	q.Get("data", &t_data)

	// check for unchanged data
	if btype != t_btype {
		t.Fatal("btype mismatch")
	}
	if flags != t_flags {
		t.Fatal("flags mismatch")
	}
	if name != t_name {
		t.Fatal("name mismatch")
	}
	if !bytes.Equal(data, t_data) {
		t.Fatal("data mismatch")
	}
}