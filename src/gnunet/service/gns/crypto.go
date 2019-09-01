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
