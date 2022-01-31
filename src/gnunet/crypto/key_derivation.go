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

package crypto

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/math"
	"golang.org/x/crypto/hkdf"
)

// DeriveH derives an integer 'h' from the arguments.
func DeriveH(zkey *ZoneKey, label, context string) *math.Int {
	prk := hkdf.Extract(sha512.New, zkey.KeyData, []byte("key-derivation"))
	data := append([]byte(label), []byte(context)...)
	rdr := hkdf.Expand(sha256.New, prk, data)
	b := make([]byte, 64)
	rdr.Read(b)
	h := math.NewIntFromBytes(b)
	switch zkey.Type {
	case ZONE_PKEY, ZONE_EDKEY:
		return h.Mod(ed25519.GetCurve().N)
	}
	return nil
}

// DerivePublicKey "shifts" a public key 'Q' to a new point 'P' where
// P = h*Q with 'h' being a factor derived from the arguments.
func DerivePublicKey(zkey *ZoneKey, label string, context string) *ZoneKey {
	h := DeriveH(zkey, label, context)
	switch zkey.Type {
	case ZONE_PKEY, ZONE_EDKEY:
		k := zkey.Key().(*ed25519.PublicKey)
		return NewZoneKey(zkey.Type, k.Mult(h))
	}
	return nil
}
