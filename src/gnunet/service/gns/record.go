package gns

import (
	"gnunet/crypto"
)

type SignedBlockData struct {
	Purpose *crypto.SignaturePurpose // Size and purpose of signature (8 bytes)
	Expire  uint64                   `order:"big"` // Expiration time of the block.
	Data    []byte                   `size:"*"`    // (encrypted) data
}

type GNSBlock struct {
	Signature []byte `size:"64"` // Signature of the block.
	DerivKey  []byte `size:"32"` // Derived key used for signing
	Block     *SignedBlockData
}

func (b *GNSBlock) String() string {
	return "GNSBlock{}"
}

func NewGNSBlock() *GNSBlock {
	return &GNSBlock{
		Signature: make([]byte, 64),
		DerivKey:  make([]byte, 32),
		Block: &SignedBlockData{
			Data: nil,
		},
	}
}

type GNSRecord struct {
}
