package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"golang.org/x/crypto/twofish"
)

// Symmetric encryption in GNUnet uses a two-layer scheme:
// * Encryption: OUT = twofish_cfb(aes_cfb(IN))
// * Decryption: OUT = aes_cfb(twofish_cfb(IN))

// SymmetricKey is a key for the GNUnet-specific two-layer encryption scheme.
type SymmetricKey struct {
	AESKey     []byte `size:"32"` // key for AES-CFB
	TwofishKey []byte `size:"32"` // key for Twofish-CFB
}

// NewSymmetricKey generates a new (random) symmetric key.
func NewSymmetricKey() *SymmetricKey {
	skey := &SymmetricKey{
		AESKey:     make([]byte, 32),
		TwofishKey: make([]byte, 32),
	}
	rand.Read(skey.AESKey)
	rand.Read(skey.TwofishKey)
	return skey
}

// SymmetricIV is an initialization vector for the GNUnet-specific two-layer
// encryption scheme.
type SymmetricIV struct {
	AESIv     []byte `size:"16"` // IV for AES-CFB
	TwofishIv []byte `size:"16"` // IV for Twofish-CFB
}

// NewSymmetricIV generates a new (random) initialization vector.
func NewSymmetricIV() *SymmetricIV {
	iv := &SymmetricIV{
		AESIv:     make([]byte, 16),
		TwofishIv: make([]byte, 16),
	}
	rand.Read(iv.AESIv)
	rand.Read(iv.TwofishIv)
	return iv
}

// SymmetricDecrypt decrypts the data with given key and initialization vector.
func SymmetricDecrypt(data []byte, skey *SymmetricKey, iv *SymmetricIV) ([]byte, error) {
	// Decrypt with Twofish CFB stream cipher
	tf, err := twofish.NewCipher(skey.TwofishKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(tf, iv.TwofishIv)
	out := make([]byte, len(data))
	stream.XORKeyStream(out, data)

	// Decrypt with AES CFB stream cipher
	aes, err := aes.NewCipher(skey.AESKey)
	if err != nil {
		return nil, err
	}
	stream = cipher.NewCFBDecrypter(aes, iv.AESIv)
	stream.XORKeyStream(out, out)
	return out, nil
}

// SymmetricEncrypt encrypts the data with given key and initialization vector.
func SymmetricEncrypt(data []byte, skey *SymmetricKey, iv *SymmetricIV) ([]byte, error) {
	// Encrypt with AES CFB stream cipher
	aes, err := aes.NewCipher(skey.AESKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(aes, iv.AESIv)
	out := make([]byte, len(data))
	stream.XORKeyStream(out, data)

	// Encrypt with Twofish CFB stream cipher
	tf, err := twofish.NewCipher(skey.TwofishKey)
	if err != nil {
		return nil, err
	}
	stream = cipher.NewCFBEncrypter(tf, iv.TwofishIv)
	stream.XORKeyStream(out, out)
	return out, nil
}
