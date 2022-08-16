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

package dht

import "testing"

func TestGetActions(t *testing.T) {
	var data = [][]bool{
		// closest, demux, approx => doResult, doForward
		//
		//	|  N  |  N  |  N  | => |  N  |  Y  |  Forward GET msg to neighbors
		//	|  Y  |  N  |  N  | => |  Y  |  N  |  Return block if in DHT
		//	|  N  |  N  |  Y  | => |  N  |  Y  |  Forward GET msg to neighbors
		//	|  Y  |  N  |  Y  | => |  Y  |  N  |  Return best-match block from DHT
		//	|  N  |  Y  |  N  | => |  N  |  Y  |  Forward GET msg to neighbors
		//	|  Y  |  Y  |  N  | => |  Y  |  Y  |  Return block if in DHT and forward GET
		//	|  N  |  Y  |  Y  | => |  Y  |  Y  |  Return best-match block from DHT than forward GET
		//	|  Y  |  Y  |  Y  | => |  Y  |  N  |  Return best-match block from DHT
		//
		{false, false, false, false, true},
		{true, false, false, true, false},
		{false, false, true, false, true},
		{true, false, true, true, false},
		{false, true, false, false, true},
		{true, true, false, true, true},
		{false, true, true, true, true},
		{true, true, true, true, false},
	}
	for i, d := range data {
		r1, r2 := getActions(d[0], d[1], d[2])
		if r1 != d[3] || r2 != d[4] {
			t.Errorf("Failed entry #%d: %v -- got: %v,%v", i, d, r1, r2)
		}
	}
}

func TestPutActions(t *testing.T) {
	var data = [][]bool{
		// closest, demux => doStore, doForward
		//
		//	|  N  |  N  | => |  N  |  Y  |  Forward PUT msg
		//	|  Y  |  N  | => |  Y  |  N  |  store block in DHT
		//	|  N  |  Y  | => |  Y  |  Y  |  Store block in DHT and forward PUT msg
		//	|  Y  |  Y  | => |  Y  |  Y  |  Store block in DHT and forward PUT msg
		//
		{false, false, false, true},
		{true, false, true, false},
		{false, true, true, true},
		{true, true, true, true},
	}
	for i, d := range data {
		r1, r2 := putActions(d[0], d[1])
		if r1 != d[2] || r2 != d[3] {
			t.Errorf("Failed entry #%d: %v -- got: %v,%v", i, d, r1, r2)
		}
	}
}
