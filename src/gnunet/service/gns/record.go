package gns

import (
	"fmt"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"gnunet/crypto"
)

var (
	ErrBlockNotDecrypted = fmt.Errorf("GNS block not decrypted")
)

type GNSRecord struct {
	Expire   uint64 `order:"big"`     // Expiration time of the record
	DataSize uint32 `order:"big"`     // size of the data section
	Type     uint32 `order:"big"`     // Record type
	Flag     uint32 `order:"big"`     // Flags
	Data     []byte `size:"DataSize"` // Record data
}

type GNSRecordSet struct {
	Count   uint32       `order:"big"`  // number of resource records
	Records []*GNSRecord `size:"Count"` // list of resource records
}

type SignedBlockData struct {
	Purpose *crypto.SignaturePurpose // Size and purpose of signature (8 bytes)
	Expire  uint64                   `order:"big"` // Expiration time of the block.
	Data    []byte                   `size:"*"`    // (encrypted) GNSRecordSet
}

type GNSBlock struct {
	Signature  []byte `size:"64"` // Signature of the block.
	DerivedKey []byte `size:"32"` // Derived key used for signing
	Block      *SignedBlockData

	checked   bool // block integrity checked
	verified  bool // block signature verified (internal)
	decrypted bool // block data decrypted (internal)
}

func (b *GNSBlock) String() string {
	return fmt.Sprintf("GNSBlock{Verified=%v,Decrypted=%v,data=[%d]}",
		b.verified, b.decrypted, len(b.Block.Data))
}

func (b *GNSBlock) Records() ([]*GNSRecord, error) {
	// check if block is decrypted
	if !b.decrypted {
		return nil, ErrBlockNotDecrypted
	}
	// parse block data into record set
	rs := new(GNSRecordSet)
	if err := data.Unmarshal(rs, b.Block.Data); err != nil {
		return nil, err
	}
	return rs.Records, nil
}

func (b *GNSBlock) Verify(zoneKey *ed25519.PublicKey, label string) (err error) {
	// Integrity check performed
	b.checked = true

	// verify derived key
	dkey := ed25519.NewPublicKeyFromBytes(b.DerivedKey)
	dkey2 := crypto.DerivePublicKey(zoneKey, label, "gns")
	if !dkey.Q.Equals(dkey2.Q) {
		return fmt.Errorf("Invalid signature key for GNS Block")
	}
	// verify signature
	var (
		sig *ed25519.EcSignature
		buf []byte
		ok  bool
	)
	if sig, err = ed25519.NewEcSignatureFromBytes(b.Signature); err != nil {
		return
	}
	if buf, err = data.Marshal(b.Block); err != nil {
		return
	}
	if ok, err = dkey.EcVerify(buf, sig); err == nil && !ok {
		err = fmt.Errorf("Signature verification failed for GNS block")
	}
	b.verified = true
	return
}

func (b *GNSBlock) Decrypt(zoneKey *ed25519.PublicKey, label string) (err error) {
	// decrypt payload
	b.Block.Data, err = DecryptBlock(b.Block.Data, zoneKey, label)
	b.decrypted = true
	return
}

func NewGNSBlock() *GNSBlock {
	return &GNSBlock{
		Signature:  make([]byte, 64),
		DerivedKey: make([]byte, 32),
		Block: &SignedBlockData{
			Data: nil,
		},
		checked:   false,
		verified:  false,
		decrypted: false,
	}
}
