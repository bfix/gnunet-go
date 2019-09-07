package crypto

import (
	"github.com/bfix/gospel/crypto/ed25519"
)

// SharedSecret computes a 64 byte shared secret
// between (prvA,pubB) and (prvB,pubA).
func SharedSecret(prv *ed25519.PrivateKey, pub *ed25519.PublicKey) *HashCode {
	ss := pub.Mult(prv.D).Q.X().Bytes()
	return Hash(ss)
}
