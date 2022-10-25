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

package crypto

import (
	"bytes"
	"encoding/hex"
	"gnunet/enums"
	"testing"
)

func TestEdKeyCreate(t *testing.T) {
	// create private key
	zp, err := NewZonePrivate(enums.GNS_TYPE_EDKEY, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(zp.ID())
}

func TestDeriveEDKEY(t *testing.T) {
	// create new key pair
	zp, err := NewZonePrivate(enums.GNS_TYPE_EDKEY, nil)
	if err != nil {
		t.Fatal(err)
	}
	zk := zp.Public()

	// derive keys
	dzp, _, err := zp.Derive("@", "gns")
	if err != nil {
		t.Fatal(err)
	}
	dzk, _, err := zk.Derive("@", "gns")
	if err != nil {
		t.Fatal(err)
	}
	// check resuts
	if !bytes.Equal(dzp.Public().Bytes(), dzk.Bytes()) {
		t.Logf("dzp.Public = %s", hex.EncodeToString(dzp.Public().Bytes()))
		t.Logf("dzk = %s", hex.EncodeToString(dzk.Bytes()))
		t.Fatal("derive mismatch")
	}
}
