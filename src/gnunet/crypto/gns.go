package crypto

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/bfix/gospel/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

// DeriveBlockKey returns a symmetric key and initialization vector to decipher a GNS block.
func DeriveBlockKey(label string, pub *ed25519.PublicKey) (iv *SymmetricIV, skey *SymmetricKey) {
	// generate symmetric key
	prk := hkdf.Extract(sha512.New, []byte(label), pub.Bytes())
	rdr := hkdf.Expand(sha256.New, prk, []byte("gns-aes-ctx-key"))
	skey = NewSymmetricKey()
	rdr.Read(skey.AESKey)
	rdr.Read(skey.TwofishKey)
	// generate initialization vector
	rdr = hkdf.Expand(sha256.New, prk, []byte("gns-aes-ctx-iv"))
	iv = NewSymmetricIV()
	rdr.Read(iv.AESIv)
	rdr.Read(iv.TwofishIv)
	return
}

// DecryptBlock for a given zone and label.
func DecryptBlock(data []byte, zoneKey *ed25519.PublicKey, label string) (out []byte, err error) {
	// derive key material for decryption
	iv, skey := DeriveBlockKey(label, zoneKey)
	// perform decryption
	return SymmetricDecrypt(data, skey, iv)
}
