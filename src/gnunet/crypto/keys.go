package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"

	"gnunet/crypto/ed25519"
	"gnunet/util"
)

// Error codes
var (
	ErrInvalidPrivateKeyData = fmt.Errorf("Invalid private key data")
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

// Verify checks a signature of a message.
func (pub *PublicKey) Verify(msg []byte, sig *Signature) bool {
	hv := sha512.Sum512(msg)
	return ed25519.Verify(pub.key, hv[:], sig.Bytes())
}

//----------------------------------------------------------------------
// Private Key
//----------------------------------------------------------------------

// PrivateKey is a Ed25519 private key.
type PrivateKey struct {
	key ed25519.PrivateKey // private key data (seed||public_key)
	d   *big.Int           // HACK! "real" private key
}

// PrivateKeyFromSeed returns a private key for a given seed.
func PrivateKeyFromSeed(seed []byte) *PrivateKey {
	k := &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
	// HACK! Save the "real" private key 'd' for later use
	md := sha512.Sum512(seed)
	d := util.Reverse(md[:32])
	d[0] = (d[0] & 0x3f) | 0x40
	d[31] &= 0xf8
	k.d = new(big.Int).SetBytes(d)
	return k
}

// D returns the "real" private key (HACK!)
func (prv *PrivateKey) D() *big.Int {
	return prv.d
}

// Public returns the public key for a private key.
func (prv *PrivateKey) Public() *PublicKey {
	return &PublicKey{
		key: util.Clone(prv.key[ed25519.PublicKeySize:]),
	}
}

// Sign creates a signature for a message.
func (prv *PrivateKey) Sign(msg []byte) (*Signature, error) {
	hv := sha512.Sum512(msg)
	sig, err := prv.key.Sign(rand.Reader, hv[:], crypto.Hash(0))
	return NewSignatureFromBytes(sig), err
}

// NewKeypair creates a new Ed25519 key pair.
func NewKeypair() (*PublicKey, *PrivateKey, error) {
	pub, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{key: pub}, &PrivateKey{key: prv}, nil
}
