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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/math"
	"golang.org/x/crypto/hkdf"
)

//======================================================================
// PKEY implementation for GNS zone crypto:
// ----------------------------------------
// Based on the Ed25519 curve. Private keys are defined by a scalar
// and signatures are based on a deterministic variant of ECDSA.
//======================================================================

// register our implementation
func init() {
	zoneImpl[ZONE_PKEY] = &ZoneImplementation{
		NewPrivate:    func() ZonePrivateImpl { return &PKEYPrivateImpl{} },
		PrivateSize:   32,
		NewPublic:     func() ZoneKeyImpl { return &PKEYPublicImpl{} },
		PublicSize:    32,
		NewSignature:  func() ZoneSigImpl { return &PKEYSigImpl{} },
		SignatureSize: 64,
	}
}

//----------------------------------------------------------------------
// Private key
//----------------------------------------------------------------------

// PKEYPublicImpl implements the public key scheme.
type PKEYPublicImpl struct {
	ztype uint32
	pub   *ed25519.PublicKey
}

// Init instance from binary data. The data represents a big integer
// (in big-endian notation) for the private scalar d.
func (pk *PKEYPublicImpl) Init(data []byte) error {
	pk.ztype = ZONE_PKEY
	pk.pub = ed25519.NewPublicKeyFromBytes(data)
	return nil
}

// Bytes returns a binary representation of the instance suitable for
// consumption in 'Init()'.
func (pk *PKEYPublicImpl) Bytes() []byte {
	return pk.pub.Bytes()
}

// Derive a public key from this key based on a big integer
// (key blinding). Returns the derived key and the blinding value.
func (pk *PKEYPublicImpl) Derive(h *math.Int) (ZoneKeyImpl, *math.Int) {
	// limit to allowed value range
	h = h.Mod(ed25519.GetCurve().N)
	derived := pk.pub.Mult(h)
	dPk := &PKEYPublicImpl{
		pk.ztype,
		derived,
	}
	return dPk, h
}

// Encrypt binary data (of any size). Output can be larger than input
func (pk *PKEYPublicImpl) Encrypt(data []byte, label string, expires util.AbsoluteTime) ([]byte, error) {
	return pk.cipher(true, data, label, expires)
}

// Decrypt binary data (of any size). Output can be smaller than input
func (pk *PKEYPublicImpl) Decrypt(data []byte, label string, expires util.AbsoluteTime) ([]byte, error) {
	return pk.cipher(false, data, label, expires)
}

// Verify a signature for binary data
func (pk *PKEYPublicImpl) Verify(data []byte, zs *ZoneSignature) (ok bool, err error) {
	var sig *ed25519.EcSignature
	if sig, err = ed25519.NewEcSignatureFromBytes(zs.Signature); err != nil {
		return
	}
	return pk.pub.EcVerify(data, sig)
}

// BlockKey return the symmetric key (and initialization vector) based on
// label and expiration time.
func (pk *PKEYPublicImpl) BlockKey(label string, expires util.AbsoluteTime) (skey []byte) {
	// generate symmetric key
	skey = make([]byte, 48)
	kd := pk.pub.Bytes()
	prk := hkdf.Extract(sha512.New, kd, []byte("gns-aes-ctx-key"))
	rdr := hkdf.Expand(sha256.New, prk, []byte(label))
	rdr.Read(skey[:32])

	// assemble initialization vector
	iv := &struct {
		Nonce      []byte            `size:"4"`    // 32 bit Nonce
		Expiration util.AbsoluteTime ``            // Expiration time of block
		Counter    uint32            `order:"big"` // Block counter
	}{
		Nonce:      make([]byte, 4),
		Expiration: expires,
		Counter:    1,
	}
	prk = hkdf.Extract(sha512.New, kd, []byte("gns-aes-ctx-iv"))
	rdr = hkdf.Expand(sha256.New, prk, []byte(label))
	rdr.Read(iv.Nonce)
	buf, _ := data.Marshal(iv)
	copy(skey[32:], buf)
	return
}

// cipher implements symmetric en/-decryption (for block data).
func (pk *PKEYPublicImpl) cipher(encrypt bool, data []byte, label string, expires util.AbsoluteTime) (out []byte, err error) {
	// derive key material for decryption
	skey := pk.BlockKey(label, expires)

	// En-/decrypt with AES CTR stream cipher
	var blk cipher.Block
	if blk, err = aes.NewCipher(skey[:32]); err != nil {
		return
	}
	stream := cipher.NewCTR(blk, skey[32:])
	out = make([]byte, len(data))
	stream.XORKeyStream(out, data)
	return
}

//----------------------------------------------------------------------
// Private key
//----------------------------------------------------------------------

// PKEYPrivateImpl implements the private key scheme.
type PKEYPrivateImpl struct {
	PKEYPublicImpl

	prv *ed25519.PrivateKey
}

// Init instance from binary data. The data represents a big integer
// (in big-endian notation) for the private scalar d.
func (pk *PKEYPrivateImpl) Init(data []byte) error {
	d := math.NewIntFromBytes(data)
	pk.prv = ed25519.NewPrivateKeyFromD(d)
	pk.ztype = ZONE_PKEY
	pk.pub = pk.prv.Public()
	return nil
}

// Bytes returns a binary representation of the instance suitable for
// consumption in 'Init()'.
func (pk *PKEYPrivateImpl) Bytes() []byte {
	return pk.prv.Bytes()
}

// Public returns the associate public key implementation.
func (pk *PKEYPrivateImpl) Public() ZoneKeyImpl {
	return &pk.PKEYPublicImpl
}

// Derive a public key from this key based on a big integer
// (key blinding). Returns the derived key and the blinding value.
func (pk *PKEYPrivateImpl) Derive(h *math.Int) (ZonePrivateImpl, *math.Int) {
	// limit to allowed value range
	h = h.Mod(ed25519.GetCurve().N)
	derived := pk.prv.Mult(h)
	dPk := &PKEYPrivateImpl{
		PKEYPublicImpl{
			pk.ztype,
			derived.Public(),
		},
		derived,
	}
	return dPk, h
}

// Verify a signature for binary data
func (pk *PKEYPrivateImpl) Sign(data []byte) (*ZoneSignature, error) {
	s, err := pk.prv.EcSign(data)
	if err != nil {
		return nil, err
	}
	sd := s.Bytes()
	sigImpl := new(PKEYSigImpl)
	sigImpl.Init(sd)
	sig := &ZoneSignature{
		ZoneKey{
			Type:    pk.ztype,
			KeyData: pk.pub.Bytes(),
		},
		sd,
		sigImpl,
	}
	return sig, nil
}

//----------------------------------------------------------------------
// Signature
//----------------------------------------------------------------------

// ZoneSigImpl defines the methods for a signature object.
type PKEYSigImpl struct {
	sig *ed25519.EcSignature
}

// Init instance from binary data. The data represents a big integers
// R and S of the signature.
func (s *PKEYSigImpl) Init(data []byte) (err error) {
	s.sig, err = ed25519.NewEcSignatureFromBytes(data)
	return
}

// Bytes returns a binary representation of the instance suitable for
// consumption in 'Init()'.
func (s *PKEYSigImpl) Bytes() []byte {
	return s.sig.Bytes()
}
