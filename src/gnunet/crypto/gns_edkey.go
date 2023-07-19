// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2023 Bernd Fix  >Y<
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
	"errors"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/math"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

//======================================================================
// EDKEY implementation for GNS zone crypto:
// ----------------------------------------
// Based on the Ed25519 curve. Private keys are defined by a seed
// and signatures are based on EdDSA.
//======================================================================

// register our implementation
func init() {
	zoneImpl[ZONE_EDKEY] = &ZoneImplementation{
		NewPrivate:    func() ZonePrivateImpl { return &EDKEYPrivateImpl{} },
		PrivateSize:   32,
		NewPublic:     func() ZoneKeyImpl { return &EDKEYPublicImpl{} },
		PublicSize:    32,
		NewSignature:  func() ZoneSigImpl { return &EDKEYSigImpl{} },
		SignatureSize: 64,
	}
}

//----------------------------------------------------------------------
// Public key
//----------------------------------------------------------------------

// EDKEYPublicImpl implements the EDKEY public key scheme.
type EDKEYPublicImpl struct {
	ztype enums.GNSType
	pub   *ed25519.PublicKey
}

// Init instance from binary data. The data represents a binary
// representation of a curve point (as defined in RFC 8032).
func (pk *EDKEYPublicImpl) Init(data []byte) error {
	pk.ztype = ZONE_EDKEY
	pk.pub = ed25519.NewPublicKeyFromBytes(data)
	return nil
}

// Bytes returns a binary representation of the instance suitable for
// consumption in 'Init()'.
func (pk *EDKEYPublicImpl) Bytes() []byte {
	return pk.pub.Bytes()
}

// Derive a public key from this key based on a big integer
// (key blinding). Returns the derived key and the blinding value.
func (pk *EDKEYPublicImpl) Derive(h *math.Int) (dPk ZoneKeyImpl, hOut *math.Int, err error) {
	// limit to allowed value range (see LSD0001 spec, 5.1.2.)
	hOut = h.Mod(ed25519.GetCurve().N)
	derived := pk.pub.Mult(hOut)
	dPk = &EDKEYPublicImpl{
		pk.ztype,
		derived,
	}
	return
}

// Encrypt binary data (of any size). Output can be larger than input
func (pk *EDKEYPublicImpl) Encrypt(data []byte, label string, expires util.AbsoluteTime) (out []byte, err error) {
	// derive key material for decryption
	skey, _ := pk.BlockKey(label, expires)

	// En-/decrypt with XSalsa20-Poly1305 cipher
	var key [32]byte
	var nonce [24]byte
	copy(key[:], skey[:32])
	copy(nonce[:], skey[32:])
	out = secretbox.Seal(nil, data, &nonce, &key)
	return
}

// Decrypt binary data (of any size). Output can be smaller than input
func (pk *EDKEYPublicImpl) Decrypt(data []byte, label string, expires util.AbsoluteTime) (out []byte, err error) {
	// derive key material for decryption
	skey, _ := pk.BlockKey(label, expires)

	// En-/decrypt with XSalsa20-Poly1305 cipher
	var (
		key   [32]byte
		nonce [24]byte
		ok    bool
	)
	copy(key[:], skey[:32])
	copy(nonce[:], skey[32:])
	if out, ok = secretbox.Open(nil, data, &nonce, &key); !ok {
		err = errors.New("XSalsa20-Poly1305 open failed")
	}
	return
}

// Verify a signature for binary data
func (pk *EDKEYPublicImpl) Verify(data []byte, zs *ZoneSignature) (ok bool, err error) {
	var sig *ed25519.EdSignature
	if sig, err = ed25519.NewEdSignatureFromBytes(zs.Signature); err != nil {
		return
	}
	return pk.pub.EdVerify(data, sig)
}

// BlockKey return the symmetric key (and initialization vector) based on
// label and expiration time.
func (pk *EDKEYPublicImpl) BlockKey(label string, expire util.AbsoluteTime) (skey []byte, nLen int) {
	// generate symmetric key
	skey = make([]byte, 56)
	kd := pk.Bytes()
	prk := hkdf.Extract(sha512.New, kd, []byte("gns-xsalsa-ctx-key"))
	rdr := hkdf.Expand(sha256.New, prk, []byte(label))
	if _, err := rdr.Read(skey[:32]); err != nil {
		logger.Printf(logger.ERROR, "[EDKEYPublicImpl.BlockKey] failed: %s", err.Error())
	}
	// assemble initialization vector
	iv := &struct {
		Nonce  []byte            `size:"16"` // Nonce
		Expire util.AbsoluteTime ``          // Expiration time of block
	}{
		Nonce:  make([]byte, 16),
		Expire: expire,
	}
	prk = hkdf.Extract(sha512.New, kd, []byte("gns-xsalsa-ctx-iv"))
	rdr = hkdf.Expand(sha256.New, prk, []byte(label))
	if _, err := rdr.Read(iv.Nonce); err != nil {
		logger.Printf(logger.ERROR, "[EDKEYPublicImpl.BlockKey] failed: %s", err.Error())
	}
	buf, _ := data.Marshal(iv)
	copy(skey[32:], buf)
	nLen = 16
	return
}

// ID returns the GNUnet identifier for a public zone key
func (pk *EDKEYPublicImpl) ID() string {
	return util.EncodeBinaryToString(asBytes(enums.GNS_TYPE_EDKEY, pk.pub.Bytes()))
}

//----------------------------------------------------------------------
// Private key
//----------------------------------------------------------------------

// EDKEYPrivateImpl implements the private key scheme.
type EDKEYPrivateImpl struct {
	EDKEYPublicImpl

	seed []byte              // seed used to generate key
	prv  *ed25519.PrivateKey // private key
}

// Init instance from binary data. The data represents the seed
// used to generate the private scalar and nonce (see RFC 8032).
func (pk *EDKEYPrivateImpl) Init(data []byte) error {
	pk.seed = util.Clone(data)
	pk.prv = ed25519.NewPrivateKeyFromSeed(data)
	pk.ztype = ZONE_EDKEY
	pk.pub = pk.prv.Public()
	return nil
}

// Prepare a random byte array to be used as a random private EDKEY
func (pk *EDKEYPrivateImpl) Prepare(rnd []byte) []byte {
	return rnd
}

// Bytes returns a binary representation of the instance suitable for
// consumption in 'Init()'.
func (pk *EDKEYPrivateImpl) Bytes() []byte {
	return pk.prv.Bytes()
}

// Public returns the associate public key implementation.
func (pk *EDKEYPrivateImpl) Public() ZoneKeyImpl {
	return &pk.EDKEYPublicImpl
}

// Derive a private key from this key based on a big integer
// (key blinding). Returns the derived key and the blinding value.
func (pk *EDKEYPrivateImpl) Derive(h *math.Int) (dPk ZonePrivateImpl, hOut *math.Int, err error) {
	// limit to allowed value range (see LSD0001 spec 5.1.2)
	hOut = h.Mod(ed25519.GetCurve().N)
	// derive private key
	derived := pk.prv.Mult(hOut)
	// derive nonce
	md := sha256.Sum256(append(pk.prv.Nonce, h.Bytes()...))
	derived.Nonce = md[:]
	// assemble EDKEY private key implementation
	dPk = &EDKEYPrivateImpl{
		EDKEYPublicImpl: EDKEYPublicImpl{
			pk.ztype,
			derived.Public(),
		},
		prv: derived,
	}
	return
}

// Sign binary data
func (pk *EDKEYPrivateImpl) Sign(data []byte) (sig *ZoneSignature, err error) {
	var s *ed25519.EdSignature
	if s, err = pk.prv.EdSign(data); err != nil {
		return
	}
	sd := s.Bytes()
	sigImpl := new(EDKEYSigImpl)
	if err = sigImpl.Init(sd); err != nil {
		return
	}
	sig = &ZoneSignature{
		ZoneKey{
			Type:    pk.ztype,
			KeyData: pk.pub.Bytes(),
		},
		sd,
		sigImpl,
	}
	return
}

// ID returns the GNUnet identifier for a private zone key
func (pk *EDKEYPrivateImpl) ID() string {
	return util.EncodeBinaryToString(asBytes(enums.GNS_TYPE_EDKEY, pk.seed))
}

//----------------------------------------------------------------------
// Signature
//----------------------------------------------------------------------

// ZoneSigImpl defines the methods for a signature object.
type EDKEYSigImpl struct {
	sig *ed25519.EcSignature
}

// Init instance from binary data. The data represents a big integers
// R and S of the signature.
func (s *EDKEYSigImpl) Init(data []byte) (err error) {
	s.sig, err = ed25519.NewEcSignatureFromBytes(data)
	return
}

// Bytes returns a binary representation of the instance suitable for
// consumption in 'Init()'.
func (s *EDKEYSigImpl) Bytes() []byte {
	return s.sig.Bytes()
}
