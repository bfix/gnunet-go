package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"math/big"

	"gnunet/crypto/hkdf"
)

////////////////////////////////////////////////////////////////////////

// DeriveH
func (pub *PublicKey) DeriveH(label, context string) *big.Int {
	prk := hkdf.Extract(sha512.New, pub.Bytes(), []byte("key-derivation"))
	data := append([]byte(label), []byte(context)...)
	rdr := hkdf.Expand(sha256.New, prk, data)
	b := make([]byte, 32)
	rdr.Read(b)
	h := new(big.Int).SetBytes(b)
	return new(big.Int).Mod(h, n)
}

// PublicKeyDerive
func (pub *PublicKey) DeriveKey(label string, context string) *PublicKey {
	h := pub.DeriveH(label, context)
	return pub.Mult(h)
}
