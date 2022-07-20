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
	"encoding/base64"
	"testing"

	"github.com/bfix/gospel/crypto/ed25519"
)

func TestPeerIDString(t *testing.T) {
	seed := "iYK1wSi5XtCP774eNFk1LYXqKlOPEpwKBw+2/bMkE24="
	data, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		t.Fatal(err)
	}
	prv := ed25519.NewPrivateKeyFromSeed(data)
	pub := prv.Public()
	id := NewPeerID(pub.Bytes())
	t.Log(id)
}
