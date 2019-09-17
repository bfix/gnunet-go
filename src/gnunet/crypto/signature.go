package crypto

type SignaturePurpose struct {
	Size    uint32 `order:"big"` // How many bytes are signed?
	Purpose uint32 `order:"big"` // Signature purpose
}
