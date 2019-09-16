package crypto

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/math"
	"golang.org/x/crypto/hkdf"
)

var (
	ED25519_N = ed25519.GetCurve().N
)

// DeriveH derives an integer 'h' from the arguments.
func DeriveH(pub *ed25519.PublicKey, label, context string) *math.Int {
	prk := hkdf.Extract(sha512.New, pub.Bytes(), []byte("key-derivation"))
	data := append([]byte(label), []byte(context)...)
	rdr := hkdf.Expand(sha256.New, prk, data)
	b := make([]byte, 64)
	rdr.Read(b)
	return math.NewIntFromBytes(b).Mod(ED25519_N)
}

// DerivePublicKey "shifts" a public key 'Q' to a new point 'P' where
// P = h*Q with 'h' being a factor derived from the arguments.
func DerivePublicKey(pub *ed25519.PublicKey, label string, context string) *ed25519.PublicKey {
	h := DeriveH(pub, label, context)
	return pub.Mult(h)
}
