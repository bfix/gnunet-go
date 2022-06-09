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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/math"
	"golang.org/x/crypto/hkdf"
)

//======================================================================
// All zone-related cryptography in GNS is encapsulated in three
// distinct types: ZonePrivate, ZoneKey (public) and ZoneSignature.
// To enable crypto-agility, these types are implemented in a generic
// way - mostly as byte arrays holding the specific representation of a
// crypto implementation.
//
// Currently two key systems are implemented:
//   * PKEY: Ed25519 keys with private scalar and ECDSA signatures
//   * EDKEY: Ed25519 keys for EdDSA signatures (Ed25519 standard)
//
// It is easy to implement new crypto schemes as long as the following
// criteria are met:
//   * It is an asymmetric crypto scheme (with private and public key)
//   * It can encrypt data with a public key and decrypt it with the
//     corresponding private key. How that is done is completely up to
//     the specific implementation.
//   * It can sign data with the private key and verify it with the
//     corresponding public key.
//   * It can do key blinding (public and private) based on a 64 byte
//     byte array. How that is done is up to the specific implementation.
//
// The way to add new zone crypto implementation is as follows; as an
// example the RSA crypto scheme is outlined:
//
//   (1) Register/define a new GNS_TYPE_RSAKEY
//   (2) Add ZONE_RSAKEY and GNS_TYPE_RSAKEY to the "Zone types"
//       declarations in this file.
//   (3) Code the implementation in a file named `gns_rsakey.go`:
//       You have to implement three interfaces (ZonePrivateImpl,
//       ZoneKeyImpl and ZoneSigImpl) in three separate custom types.
//       Additionally an instantiation function (zero value) must be
//       defined for all three custom types (like 'NewRSAPrivate()'
//       taking no arguments and returning an empty new instance.
//   (4) In the 'init()' method of your source file, register the
//       implementation in the "Zone implementations" below with:
//           zoneImpl[ZONE_RSAKEY] = &ZoneImplementation{
//               NewPrivate: NewRSAPrivate,
//               PrivateSize: 256,
//               NewPublic: NewRSAPublic,
//               PublicSize: 270.
//               NewSignature: newRSASignature,
//               SignatureSize: 512,
//           }
//   Review a provided implementation (like `gns_edkey.go`) as an
//   example on how to create a custom GNS zone crypto.
//   (5) Add the zone type to the GNS block handler in file
//       `service/gns/block_handler.go`:
//           ;
//           enums.GNS_TYPE_RSAKEY:     NewZoneHandler,
//           ;
//
//======================================================================

//----------------------------------------------------------------------
// Implementation interfaces
//----------------------------------------------------------------------

// ZoneAbstractImpl is an abstract interface used in derived interfaces
type ZoneAbstractImpl interface {
	// Init the instance from given binary representation
	Init(data []byte) error

	// Bytes returns the binary representation (can be used with 'init()')
	Bytes() []byte
}

// ZoneKeyImpl defines the methods for a public zone key.
type ZoneKeyImpl interface {
	ZoneAbstractImpl

	// Derive a zone key from this zone key based on a big integer
	// (key blinding). Returns the derived key and the blinding value.
	Derive(h *math.Int) (ZoneKeyImpl, *math.Int)

	// BlockKey returns the key for block en-/decryption
	BlockKey(label string, expires util.AbsoluteTime) (skey []byte)

	// Encrypt binary data (of any size). Output can be larger than input
	Encrypt(data []byte, label string, expires util.AbsoluteTime) ([]byte, error)

	// Decrypt data (of any size). Output can be smaller than input
	Decrypt(data []byte, label string, expires util.AbsoluteTime) ([]byte, error)

	// Verify a signature for binary data
	Verify(data []byte, sig *ZoneSignature) (bool, error)
}

// ZonePrivateImpl defines the methods for a private zone key.
type ZonePrivateImpl interface {
	ZoneAbstractImpl

	// Derive a private key from this zone key based on a big integer
	// (key blinding). Returns the derived key and the blinding value.
	Derive(h *math.Int) (ZonePrivateImpl, *math.Int)

	// Sign binary data and return the signature
	Sign(data []byte) (*ZoneSignature, error)

	// Public returns the associated public key
	Public() ZoneKeyImpl
}

// ZoneSigImpl defines the methods for a signature object.
type ZoneSigImpl interface {
	ZoneAbstractImpl
}

//----------------------------------------------------------------------
// Zone types
//----------------------------------------------------------------------
var (
	ZONE_PKEY  = uint32(enums.GNS_TYPE_PKEY)
	ZONE_EDKEY = uint32(enums.GNS_TYPE_EDKEY)

	// register available zone types for BlockHandler
	ZoneTypes = []enums.GNSType{
		enums.GNS_TYPE_PKEY,
		enums.GNS_TYPE_EDKEY,
	}
)

//----------------------------------------------------------------------
// Zone implementations
//----------------------------------------------------------------------

// ZoneImplementation holds factory methods and size values for a
// specific crypto implementation (based on the associated zone type)
type ZoneImplementation struct {
	NewPrivate    func() ZonePrivateImpl
	PrivateSize   uint
	NewPublic     func() ZoneKeyImpl
	PublicSize    uint
	NewSignature  func() ZoneSigImpl
	SignatureSize uint
}

// keep a mapping of available implementations
var (
	zoneImpl = make(map[uint32]*ZoneImplementation)
)

// Error codes
var (
	ErrNoImplementation = errors.New("unknown zone implementation")
)

// GetImplementation return the factory for a given zone type.
// If zje zone type is unregistered, nil is returned.
func GetImplementation(ztype uint32) *ZoneImplementation {
	if impl, ok := zoneImpl[ztype]; ok {
		return impl
	}
	return nil
}

//======================================================================
// Generic implementations:
//======================================================================

//----------------------------------------------------------------------
// Zone key (private)
//----------------------------------------------------------------------

// ZonePrivate represents the possible types of private zone keys (PKEY, EDKEY,...)
type ZonePrivate struct {
	ZoneKey

	impl ZonePrivateImpl // reference to implementation
}

// NewZonePrivate returns a new initialized ZonePrivate instance
func NewZonePrivate(ztype uint32, d []byte) (*ZonePrivate, error) {
	// get factory for given zone type
	impl, ok := zoneImpl[ztype]
	if !ok {
		return nil, ErrNoImplementation
	}
	// assemble private zone key
	zp := &ZonePrivate{
		ZoneKey{
			ztype,
			nil,
			nil,
		},
		nil,
	}
	zp.impl = impl.NewPrivate()
	zp.impl.Init(d)
	zp.ZoneKey.KeyData = zp.impl.Public().Bytes()
	zp.ZoneKey.impl = impl.NewPublic()
	zp.ZoneKey.impl.Init(zp.ZoneKey.KeyData)
	return zp, nil
}

// KeySize returns the number of bytes of a key representation.
// This method is used during serialization (Unmarshal).
func (zp *ZonePrivate) KeySize() uint {
	if impl, ok := zoneImpl[zp.Type]; ok {
		return impl.PrivateSize
	}
	return 0
}

// Derive key (key blinding)
func (zp *ZonePrivate) Derive(label, context string) (*ZonePrivate, *math.Int) {
	// get factory for given zone type
	impl := zoneImpl[zp.Type]

	// caclulate derived key
	h := deriveH(zp.impl.Bytes(), label, context)
	var derived ZonePrivateImpl
	derived, h = zp.impl.Derive(h)

	// assemble derived pivate key
	dzp := &ZonePrivate{
		ZoneKey{
			zp.Type,
			nil,
			nil,
		},
		derived,
	}
	zp.ZoneKey.KeyData = derived.Public().Bytes()
	zp.ZoneKey.impl = impl.NewPublic()
	zp.ZoneKey.impl.Init(zp.ZoneKey.KeyData)
	return dzp, h
}

// ZoneSign data with a private key
func (zp *ZonePrivate) Sign(data []byte) (sig *ZoneSignature, err error) {
	return zp.impl.Sign(data)
}

// Public returns the associated public key
func (zp *ZonePrivate) Public() *ZoneKey {
	return &zp.ZoneKey
}

//----------------------------------------------------------------------
// Zone key (public)
//----------------------------------------------------------------------

// ZoneKey represents the possible types of zone keys (PKEY, EDKEY,...)
type ZoneKey struct {
	Type    uint32 `json:"type" order:"big"`
	KeyData []byte `json:"key" size:"(KeySize)"`

	impl ZoneKeyImpl // reference to implementation
}

// NewZoneKey returns a new initialized ZoneKey instance
func NewZoneKey(d []byte) (*ZoneKey, error) {
	// read zone key from data
	zk := new(ZoneKey)
	if err := data.Unmarshal(zk, d); err != nil {
		return nil, err
	}
	// initialize implementation
	impl, ok := zoneImpl[zk.Type]
	if !ok {
		return nil, errors.New("unknown zone type")
	}
	zk.impl = impl.NewPublic()
	zk.impl.Init(zk.KeyData)
	return zk, nil
}

// KeySize returns the number of bytes of a key representation.
// This method is used during serialization (Unmarshal).
func (zk *ZoneKey) KeySize() uint {
	if impl, ok := zoneImpl[zk.Type]; ok {
		return impl.PublicSize
	}
	return 0
}

// Derive key (key blinding)
func (zk *ZoneKey) Derive(label, context string) (*ZoneKey, *math.Int) {
	h := deriveH(zk.KeyData, label, context)
	var derived ZoneKeyImpl
	derived, h = zk.impl.Derive(h)
	return &ZoneKey{
		Type:    zk.Type,
		KeyData: derived.Bytes(),
		impl:    derived,
	}, h
}

// BlockKey returns the key for block en-/decryption
func (zk *ZoneKey) BlockKey(label string, expires util.AbsoluteTime) (skey []byte) {
	return zk.impl.BlockKey(label, expires)
}

// Encrypt data
func (zk *ZoneKey) Encrypt(data []byte, label string, expire util.AbsoluteTime) ([]byte, error) {
	return zk.impl.Encrypt(data, label, expire)
}

// Decrypt data
func (zk *ZoneKey) Decrypt(data []byte, label string, expire util.AbsoluteTime) ([]byte, error) {
	return zk.impl.Decrypt(data, label, expire)
}

// Verify a zone signature
func (zk *ZoneKey) Verify(data []byte, zs *ZoneSignature) (ok bool, err error) {
	zk.withImpl()
	return zk.impl.Verify(data, zs)
}

// ID returns the human-readable zone identifier.
func (zk *ZoneKey) ID() string {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, zk.Type)
	buf.Write(zk.KeyData)
	return util.EncodeBinaryToString(buf.Bytes())
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

// withImpl ensure that an implementation reference is available
func (zk *ZoneKey) withImpl() {
	if zk.impl == nil {
		factory := zoneImpl[zk.Type]
		zk.impl = factory.NewPublic()
		zk.impl.Init(zk.KeyData)
	}
}

//----------------------------------------------------------------------
// Zone signature
//----------------------------------------------------------------------

type ZoneSignature struct {
	ZoneKey
	Signature []byte `size:"(SigSize)"` // signature data

	impl ZoneSigImpl // reference to implementation
}

// NewZoneSignature returns a new initialized ZoneSignature instance
func NewZoneSignature(d []byte) (*ZoneSignature, error) {
	// read signature
	sig := new(ZoneSignature)
	if err := data.Unmarshal(sig, d); err != nil {
		return nil, err
	}
	// initialize implementations
	impl, ok := zoneImpl[sig.Type]
	if !ok {
		return nil, errors.New("unknown zone type")
	}
	// set signature implementation
	zs := impl.NewSignature()
	zs.Init(sig.Signature)
	sig.impl = zs
	// set public key implementation
	zk := impl.NewPublic()
	zk.Init(sig.KeyData)
	sig.ZoneKey.impl = zk

	return sig, nil
}

// SigSize returns the number of bytes of a signature that can be
// verified with a given zone key. This method is used during
// serialization (Unmarshal).
func (zs *ZoneSignature) SigSize() uint {
	if impl, ok := zoneImpl[zs.Type]; ok {
		return impl.SignatureSize
	}
	return 0
}

// Key returns the associated zone key object
func (zs *ZoneSignature) Key() *ZoneKey {
	return &zs.ZoneKey
}

// Verify a signature
func (zs *ZoneSignature) Verify(data []byte) (bool, error) {
	return zs.ZoneKey.Verify(data, zs)
}

//----------------------------------------------------------------------
// Helper functions
//----------------------------------------------------------------------

// deriveH derives an integer 'h' from the arguments.
func deriveH(key []byte, label, context string) *math.Int {
	prk := hkdf.Extract(sha512.New, key, []byte("key-derivation"))
	data := append([]byte(label), []byte(context)...)
	rdr := hkdf.Expand(sha256.New, prk, data)
	b := make([]byte, 64)
	rdr.Read(b)
	return math.NewIntFromBytes(b)
}
