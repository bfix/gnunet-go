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

var scale = " kMGTPEO"

// Scale1024 returns an integer value (e.g. a size) as a human-readable
// string with scales: a size of 183467245 would result in "174,967M"
func Scale1024(n uint64) string {
	v := float64(n)
	var i int
	for i = 0; v > 1024; i++ {
		v /= 1024
	}
	if i == 0 {
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%.3f%c", v, scale[i])
}
