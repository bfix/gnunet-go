package gns

import (
	"gnunet/crypto"
)

// QueryFromPublickeyDerive calculates the DHT query for a given label in a
// given zone (identified by PKEY).
func QueryFromPublickeyDerive(pkey *crypto.PublicKey, label string) *crypto.HashCode {
	pd := pkey.DeriveKey(label, "gns")
	return crypto.Hash(pd.Bytes())
}

// DecryptBlock
func (s *GNSService) DecryptBlock(pkey *crypto.PublicKey, sig *crypto.Signature, data []byte) ([]byte, error) {
	return nil, nil
}
