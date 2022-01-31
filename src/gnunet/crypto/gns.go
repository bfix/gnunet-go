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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20/salsa"
)

// Zone types
var (
	ZONE_PKEY  = uint32(enums.GNS_TYPE_PKEY)
	ZONE_EDKEY = uint32(enums.GNS_TYPE_EDKEY)
)

//----------------------------------------------------------------------
// Zone key (private)
//----------------------------------------------------------------------

// ZonePrivate represents the possible types of private zone keys (PKEY, EDKEY,...)
type ZonePrivate struct {
	Type uint32
	Key  interface{}
}

// NewZonePrivate creates a new ZonePrivate object from a type and key reference.
func NewZonePrivate(ztype uint32, sk interface{}) *ZonePrivate {
	switch x := sk.(type) {
	case *ed25519.PrivateKey:
		if ztype != ZONE_PKEY && ztype != ZONE_EDKEY {
			return nil
		}
		return &ZonePrivate{
			Type: ztype,
			Key:  x,
		}
	}
	return nil
}

// KeySize returns the number of bytes of a key representation.
// This method is used during serialization (Unmarshal).
func (zp *ZonePrivate) KeySize() uint {
	switch zp.Type {
	case ZONE_PKEY, ZONE_EDKEY:
		return 32
	}
	return 0
}

//----------------------------------------------------------------------
// Zone key (public)
//----------------------------------------------------------------------

// ZoneKey represents the possible types of zone keys (PKEY, EDKEY,...)
type ZoneKey struct {
	Type    uint32 `json:"type"`
	KeyData []byte `json:"key" size:"(KeySize)"`
}

// NewZoneKey creates a new ZoneKey object from a type and key reference.
func NewZoneKey(ztype uint32, pk interface{}) *ZoneKey {
	switch x := pk.(type) {
	case *ed25519.PublicKey:
		if ztype != ZONE_PKEY && ztype != ZONE_EDKEY {
			return nil
		}
		return &ZoneKey{
			Type:    ztype,
			KeyData: x.Bytes(),
		}
	}
	return nil
}

// KeySize returns the number of bytes of a key representation.
// This method is used during serialization (Unmarshal).
func (zk *ZoneKey) KeySize() uint {
	switch zk.Type {
	case ZONE_PKEY, ZONE_EDKEY:
		return 32
	}
	return 0
}

// Key returns the public key of a zone
func (zk *ZoneKey) Key() interface{} {
	switch zk.Type {
	case ZONE_PKEY, ZONE_EDKEY:
		return ed25519.NewPublicKeyFromBytes(zk.KeyData)
	}
	return nil
}

// ID returns the human-readable zone identifier.
func (zk *ZoneKey) ID() string {
	return util.EncodeBinaryToString(zk.Bytes())
}

// Bytes returns all bytes of a zone key
func (zk *ZoneKey) Bytes() []byte {
	data, _ := data.Marshal(zk)
	return data
}

// Equal checks if two zone keys are equal
func (zk *ZoneKey) Equal(k *ZoneKey) bool {
	return bytes.Equal(zk.KeyData, k.KeyData)
}

//----------------------------------------------------------------------
// Zone signature
//----------------------------------------------------------------------

type ZoneSignature struct {
	ZoneKey
	Signature []byte `size:"(SigSize)"` // signature data
}

// SigSize returns the number of bytes of a signature that can be
// verified with a given zone key. This method is used during
// serialization (Unmarshal).
func (zs *ZoneSignature) SigSize() uint {
	switch zs.Type {
	case ZONE_PKEY, ZONE_EDKEY:
		return 64
	}
	return 0
}

// Verify a zone signature
func (zs *ZoneSignature) Verify(data []byte) (ok bool, err error) {
	ok = false
	switch zs.Type {
	case ZONE_PKEY:
		var sig *ed25519.EcSignature
		if sig, err = ed25519.NewEcSignatureFromBytes(zs.Signature); err != nil {
			return
		}
		key := zs.Key().(*ed25519.PublicKey)
		return key.EcVerify(data, sig)
	}
	err = errors.New("unknown zone type")
	return
}

// ZoneSign data with a private key
func ZoneSign(data []byte, sk *ZonePrivate) (sig *ZoneSignature, err error) {
	switch sk.Type {
	case ZONE_PKEY:
		key := sk.Key.(*ed25519.PrivateKey)
		var s *ed25519.EcSignature
		if s, err = key.EcSign(data); err == nil {
			sig = &ZoneSignature{
				ZoneKey{
					Type:    sk.Type,
					KeyData: key.Public().Bytes(),
				},
				s.Bytes(),
			}
		}
	}
	return
}

//----------------------------------------------------------------------
//----------------------------------------------------------------------

// SymmetricKey for symmetric en-/decryption
type SymmetricKey []byte

// DeriveKey returns a key and initialization vector to en-/decrypt data
// using a symmetric cipher.
func DeriveKey(label string, zkey *ZoneKey) (skey SymmetricKey) {
	// generate symmetric key and initialization vector
	skey = make([]byte, 48)
	prk := hkdf.Extract(sha512.New, zkey.KeyData, []byte("gns-aes-ctx-key"))
	rdr := hkdf.Expand(sha256.New, prk, []byte(label))
	rdr.Read(skey[:32])
	prk = hkdf.Extract(sha512.New, zkey.KeyData, []byte("gns-aes-ctx-iv"))
	rdr = hkdf.Expand(sha256.New, prk, []byte(label))
	rdr.Read(skey[32:])
	return
}

// CipherData (en-/decryption) for a given zone and label.
func CipherData(data []byte, zkey *ZoneKey, label string) (out []byte, err error) {
	// derive key material for decryption
	skey := DeriveKey(label, zkey)
	// perform decryption
	switch zkey.Type {
	case ZONE_PKEY:
		// En-/decrypt with AES CTR stream cipher
		var blk cipher.Block
		if blk, err = aes.NewCipher(skey[:32]); err != nil {
			return
		}
		stream := cipher.NewCTR(blk, skey[32:])
		out = make([]byte, len(data))
		stream.XORKeyStream(out, data)
	case ZONE_EDKEY:
		// En-/decrypt with XSalsa20-Poly1305 cipher
		n := len(data) + poly1305.TagSize
		out = make([]byte, n)
		var counter [16]byte
		var key [32]byte
		copy(counter[:], skey[32:])
		copy(key[:], skey[:32])
		salsa.XORKeyStream(out, data, &counter, &key)
	default:
		err = fmt.Errorf("unknown zone type for block decryption")
	}
	return
}
