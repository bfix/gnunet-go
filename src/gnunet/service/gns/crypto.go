package gns

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/bfix/gospel/crypto/ed25519"
	"gnunet/crypto"
	"golang.org/x/crypto/hkdf"
)

// QueryFromPublickeyDerive calculates the DHT query for a given label in a
// given zone (identified by PKEY).
func QueryFromPublickeyDerive(pkey *ed25519.PublicKey, label string) *crypto.HashCode {
	pd := crypto.DerivePublicKey(pkey, label, "gns")
	return crypto.Hash(pd.Bytes())
}

// DecryptBlock
func DecryptBlock(data []byte, zoneKey *ed25519.PublicKey, label string) (out []byte, err error) {
	// derive key material for decryption
	iv, skey := deriveBlockKey(label, zoneKey)
	// perform decryption
	return crypto.SymmetricDecrypt(data, skey, iv)
}

// Derive a symmetric key to decipher a GNS block
func deriveBlockKey(label string, pub *ed25519.PublicKey) (iv *crypto.SymmetricIV, skey *crypto.SymmetricKey) {
	// generate symmetric key
	prk := hkdf.Extract(sha512.New, []byte(label), pub.Bytes())
	rdr := hkdf.Expand(sha256.New, prk, []byte("gns-aes-ctx-key"))
	skey = crypto.NewSymmetricKey()
	rdr.Read(skey.AESKey)
	rdr.Read(skey.TwofishKey)
	// generate initialization vector
	rdr = hkdf.Expand(sha256.New, prk, []byte("gns-aes-ctx-iv"))
	iv = crypto.NewSymmetricIV()
	rdr.Read(iv.AESIv)
	rdr.Read(iv.TwofishIv)
	return
}
