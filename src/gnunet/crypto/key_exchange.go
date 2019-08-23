package crypto

import (
	"math/big"

	"gnunet/crypto/ed25519"
	"gnunet/util"
)

// Mult computes p = d*Q
func (pub *PublicKey) Mult(d *big.Int) *PublicKey {
	var (
		Q          ed25519.ExtendedGroupElement
		pge        ed25519.ProjectiveGroupElement
		a, b, zero [32]byte
	)
	// compute point Q from public key data
	copy(a[:], pub.Bytes())
	if !Q.FromBytes(&a) {
		return nil
	}
	// compute skalar product
	copy(b[:], util.Reverse(d.Bytes()))
	ed25519.GeDoubleScalarMultVartime(&pge, &b, &Q, &zero)

	// convert to public key
	pge.ToBytes(&a)
	return NewPublicKey(a[:])
}

// AffineX returns the x-coordinate of the affine point.
func (pub *PublicKey) AffineX() *big.Int {
	var (
		ge    ed25519.ExtendedGroupElement
		buf   [32]byte
		x, zi ed25519.FieldElement
	)
	copy(buf[:], pub.key)
	if !ge.FromBytes(&buf) {
		return nil
	}
	ed25519.FeInvert(&zi, &ge.Z)
	ed25519.FeMul(&x, &ge.X, &zi)
	ed25519.FeToBytes(&buf, &x)
	return new(big.Int).SetBytes(util.Reverse(buf[:]))
}

// SharedSecret computes a 64 byte shared secret
// between (prvA,pubB) and (prvB,pubA).
func SharedSecret(prv *PrivateKey, pub *PublicKey) *HashCode {
	ss := pub.Mult(prv.D()).AffineX().Bytes()
	return Hash(ss)
}
