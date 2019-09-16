package crypto

import (
	"github.com/bfix/gospel/crypto/ed25519"
)

type SignaturePurpose struct {
	Size    uint32 `order:"big"` // How many bytes are signed?
	Purpose uint32 `order:"big"` // Signature purpose
}

func EcVerify(purpose int, validate *SignaturePurpose, sig *ed25519.EcSignature, pub *ed25519.PublicKey) error {
	return nil
}
