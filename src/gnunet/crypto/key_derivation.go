package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"math/big"

	"gnunet/crypto/hkdf"
)

// DeriveH derives an integer 'h' in the range [0,n[ with 'n' being the
// order of the underlying Ed25519 curve. The value of 'h' is derived
// from the arguments.
func (pub *PublicKey) DeriveH(label, context string) *big.Int {
	prk := hkdf.Extract(sha512.New, pub.Bytes(), []byte("key-derivation"))
	data := append([]byte(label), []byte(context)...)
	rdr := hkdf.Expand(sha256.New, prk, data)
	b := make([]byte, 32)
	rdr.Read(b)
	h := new(big.Int).SetBytes(b)
	return new(big.Int).Mod(h, n)
}

// PublicKeyDerive "shifts" a public key 'Q' to a new point 'P' where
// P = h*Q with 'h' being a factor derived from the arguments.
func (pub *PublicKey) DeriveKey(label string, context string) *PublicKey {
	h := pub.DeriveH(label, context)
	return pub.Mult(h)
}
