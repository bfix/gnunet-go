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
	"testing"
	"time"
)

func TestTimeCompare(t *testing.T) {
	t1 := AbsoluteTimeNow()
	t2 := t1.Add(time.Hour)
	t3 := t1.Add(24 * time.Hour)
	tNever := AbsoluteTimeNever()

	if t1.Compare(t2) != -1 {
		t.Fatal("(1)")
	}
	if t1.Compare(t3) != -1 {
		t.Fatal("(2)")
	}
	if t2.Compare(t3) != -1 {
		t.Fatal("(3)")
	}
	if tNever.Compare(t1) != 1 {
		t.Fatal("(4)")
	}
}
