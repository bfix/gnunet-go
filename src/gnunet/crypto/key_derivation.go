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

// Curve parameters
var (
	ED25519_N = ed25519.GetCurve().N
)

// DeriveH derives an integer 'h' from the arguments.
func DeriveH(pub *ed25519.PublicKey, label, context string) *math.Int {
	prk := hkdf.Extract(sha512.New, pub.Bytes(), []byte("key-derivation"))
	data := append([]byte(label), []byte(context)...)
	rdr := hkdf.Expand(sha256.New, prk, data)
	b := make([]byte, 64)
	rdr.Read(b)
	return math.NewIntFromBytes(b).Mod(ED25519_N)
}

// DerivePublicKey "shifts" a public key 'Q' to a new point 'P' where
// P = h*Q with 'h' being a factor derived from the arguments.
func DerivePublicKey(pub *ed25519.PublicKey, label string, context string) *ed25519.PublicKey {
	h := DeriveH(pub, label, context)
	return pub.Mult(h)
}
