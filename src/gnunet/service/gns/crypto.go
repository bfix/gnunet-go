package gns

import (
	"github.com/bfix/gospel/crypto/ed25519"
	"gnunet/crypto"
)

// QueryFromPublickeyDerive calculates the DHT query for a given label in a
// given zone (identified by PKEY).
func QueryFromPublickeyDerive(pkey *ed25519.PublicKey, label string) *crypto.HashCode {
	pd := crypto.DerivePublicKey(pkey, label, "gns")
	return crypto.Hash(pd.Bytes())
}

// DecryptBlock
func (s *GNSService) DecryptBlock(pkey *ed25519.PublicKey, sig *ed25519.EcSignature, data []byte) ([]byte, error) {
	return data, nil
}
