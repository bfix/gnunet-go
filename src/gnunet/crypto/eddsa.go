package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"gnunet/util"

	"gnunet/crypto/ed25519"
)

// Error codes
var (
	ErrInvalidEdDSAPrivateKeyData = errors.New("Invalid Ed25519 private key data")
)

//----------------------------------------------------------------------
// Public key
//----------------------------------------------------------------------

// EdDSAPublicKey is a Ed25519 public key.
type EdDSAPublicKey struct {
	key ed25519.PublicKey
}

// NewEdDSAPublicKey sets the binary representation of a public key.
// The value is not checked for validity!
func NewEdDSAPublicKey(data []byte) *EdDSAPublicKey {
	return &EdDSAPublicKey{
		key: util.Clone(data),
	}
}

// Bytes returns the binary representation of a public key.
func (pub *EdDSAPublicKey) Bytes() []byte {
	return []byte(pub.key)
}

// Verify checks a signature of a data block.
func (pub *EdDSAPublicKey) Verify(data, sig []byte) bool {
	h := sha512.New()
	h.Write(data)
	hv := h.Sum(nil)
	return ed25519.Verify(pub.key, hv, sig)
}

//----------------------------------------------------------------------
// Private Key
//----------------------------------------------------------------------

// EdDSAPrivateKey is a Ed25519 private key.
type EdDSAPrivateKey struct {
	key ed25519.PrivateKey // private key data (seed||public_key)
	d   []byte             // HACK! "real" private key
}

// EdDSAPrivateKeyFromSeed returns a private key for a given seed.
func EdDSAPrivateKeyFromSeed(seed []byte) *EdDSAPrivateKey {
	k := &EdDSAPrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
	// HACK! Save the "real" private key 'd' for later use
	md := sha512.Sum512(seed)
	k.d = util.Reverse(md[:32])
	k.d[0] = (k.d[0] & 0x3f) | 0x40
	k.d[31] &= 0xf8
	return k
}

// D returns the "real" private key (HACK!)
func (prv *EdDSAPrivateKey) D() []byte {
	return util.Clone(prv.d)
}

// Public returns the public key for a private key.
func (prv *EdDSAPrivateKey) Public() *EdDSAPublicKey {
	return &EdDSAPublicKey{
		key: util.Clone(prv.key[ed25519.PublicKeySize:]),
	}
}

// Sign creates a signature for a data block.
func (prv *EdDSAPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha512.New()
	h.Write(data)
	hv := h.Sum(nil)
	return prv.key.Sign(rand.Reader, hv, crypto.Hash(0))
}

// NewPeerKeypair creates a new Ed25519 key pair.
func EdDSAKeypair() (*EdDSAPublicKey, *EdDSAPrivateKey, error) {
	pub, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &EdDSAPublicKey{key: pub}, &EdDSAPrivateKey{key: prv}, nil
}
