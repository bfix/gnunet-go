package crypto

// SignaturePurpose is the GNUnet data structure used as header for signed data.
type SignaturePurpose struct {
	Size    uint32 `order:"big"` // How many bytes are signed?
	Purpose uint32 `order:"big"` // Signature purpose
}
