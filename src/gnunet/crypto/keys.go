package crypto

import (
	"crypto/sha512"
	"fmt"

	"github.com/bfix/gospel/math"
	"gnunet/crypto/ed25519"
	"gnunet/util"
)

var (
	// Error codes
	ErrInvalidPrivateKeyData = fmt.Errorf("Invalid private key data")

	// Ed25519 curve order
	ED25519_N    = math.NewIntFromHex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
	ED25519_BITS = ED25519_N.BitLen()
)

//----------------------------------------------------------------------
// Public key
//----------------------------------------------------------------------

// PublicKey is a Ed25519 public key.
type PublicKey struct {
	key ed25519.PublicKey
}

// NewPublicKey sets the binary representation of a public key.
// The value is not checked for validity!
func NewPublicKey(data []byte) *PublicKey {
	if l := len(data); l != ed25519.PublicKeySize {
		panic(fmt.Sprintf("NewPublicKey: invalid key size (%d)", l))
	}
	return &PublicKey{
		key: util.Clone(data),
	}
}

// Bytes returns the binary representation of a public key.
func (pub *PublicKey) Bytes() []byte {
	return []byte(pub.key)
}

//----------------------------------------------------------------------
// Private Key
//----------------------------------------------------------------------

// PrivateKey is a Ed25519 private key.
type PrivateKey struct {
	key      ed25519.PrivateKey // private key data (seed||public_key)
	d        *math.Int          // HACK! "real" private key
	fromSeed bool               // generated by seed?
}

// PrivateKeyFromSeed returns a private key for a given seed.
func PrivateKeyFromSeed(seed []byte) *PrivateKey {
	k := &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
	// HACK! Save the "real" private key 'd' for later use
	md := sha512.Sum512(seed)
	d := util.Reverse(md[:ed25519.SeedSize])
	d[0] = (d[0] & 0x3f) | 0x40
	d[31] &= 0xf8
	k.d = math.NewIntFromBytes(d)
	k.fromSeed = true
	return k
}

// PrivateKeyFromD returns a private key for a given factor.
func PrivateKeyFromD(d *math.Int) *PrivateKey {
	k := &PrivateKey{
		key: make([]byte, ed25519.SeedSize+ed25519.PublicKeySize),
	}
	k.d = d
	k.fromSeed = false

	// generate public key
	var A ed25519.ExtendedGroupElement
	var dBytes [32]byte
	pos := 32 - len(d.Bytes())
	if pos < 0 {
		return nil
	}
	copy(dBytes[pos:], util.Reverse(d.Bytes()))
	ed25519.GeScalarMultBase(&A, &dBytes)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)
	copy(k.key[ed25519.SeedSize:], publicKeyBytes[:])
	return k
}

// D returns the "real" private key (HACK!)
func (prv *PrivateKey) D() *math.Int {
	return prv.d
}

// Public returns the public key for a private key.
func (prv *PrivateKey) Public() *PublicKey {
	return &PublicKey{
		key: util.Clone(prv.key[ed25519.SeedSize:]),
	}
}

// NewKeypair creates a new Ed25519 key pair.
func NewKeypair() (*PublicKey, *PrivateKey) {
	seed := make([]byte, 32)
	util.RndArray(seed)
	prv := PrivateKeyFromSeed(seed)
	pub := prv.Public()
	return pub, prv
}
