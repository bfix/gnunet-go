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
	"golang.org/x/crypto/hkdf"
)

// DeriveBlockKey returns a symmetric key and initialization vector to decipher a GNS block.
func DeriveBlockKey(label string, pub *ed25519.PublicKey) (iv *SymmetricIV, skey *SymmetricKey) {
	// generate symmetric key
	prk := hkdf.Extract(sha512.New, pub.Bytes(), []byte("gns-aes-ctx-key"))
	rdr := hkdf.Expand(sha256.New, prk, []byte(label))
	skey = NewSymmetricKey()
	rdr.Read(skey.AESKey)
	rdr.Read(skey.TwofishKey)

	// generate initialization vector
	prk = hkdf.Extract(sha512.New, pub.Bytes(), []byte("gns-aes-ctx-iv"))
	rdr = hkdf.Expand(sha256.New, prk, []byte(label))
	iv = NewSymmetricIV()
	rdr.Read(iv.AESIv)
	rdr.Read(iv.TwofishIv)
	return
}

// DecryptBlock for a given zone and label.
func DecryptBlock(data []byte, zoneKey *ed25519.PublicKey, label string) (out []byte, err error) {
	// derive key material for decryption
	iv, skey := DeriveBlockKey(label, zoneKey)
	// perform decryption
	return SymmetricDecrypt(data, skey, iv)
}
