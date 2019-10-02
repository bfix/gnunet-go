package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"golang.org/x/crypto/twofish"
)

type SymmetricKey struct {
	AESKey     []byte `size:"32"`
	TwofishKey []byte `size:"32"`
}

func NewSymmetricKey() *SymmetricKey {
	skey := &SymmetricKey{
		AESKey:     make([]byte, 32),
		TwofishKey: make([]byte, 32),
	}
	rand.Read(skey.AESKey)
	rand.Read(skey.TwofishKey)
	return skey
}

type SymmetricIV struct {
	AESIv     []byte `size:"16"`
	TwofishIv []byte `size:"16"`
}

func NewSymmetricIV() *SymmetricIV {
	iv := &SymmetricIV{
		AESIv:     make([]byte, 16),
		TwofishIv: make([]byte, 16),
	}
	rand.Read(iv.AESIv)
	rand.Read(iv.TwofishIv)
	return iv
}

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
