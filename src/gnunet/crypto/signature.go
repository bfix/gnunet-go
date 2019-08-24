package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"

	"gnunet/crypto/ed25519"
	"gnunet/util"
)

// Signature purpose constants
const (
	SIG_TEST                     = iota // Only used in test cases!
	SIG_TRANSPORT_PONG_OWN              // Confirming a particular address.
	SIG_TRANSPORT_DISCONNECT            // Confirming intent to disconnect.
	SIG_REVOCATION                      // Confirming a key revocation.
	SIG_NAMESPACE_ADVERTISEMENT         // Namespace/pseudonym advertisement.
	SIG_PEER_PLACEMENT                  // Affirm certain content (LOCation URIs).
	SIG_FS_KBLOCK                       // Obsolete, legacy value.
	SIG_FS_SBLOCK                       // Obsolete, legacy value.
	SIG_FS_NBLOCK                       // Obsolete, legacy value.
	SIG_FS_NBLOCK_KSIG                  // Obsolete, legacy value.
	SIG_RESOLVER_RESPONSE               // DNS_Advertisement
	SIG_DNS_RECORD                      //
	SIG_CHAT_MESSAGE                    // Chat message.
	SIG_CHAT_RECEIPT                    // Confirmation receipt for chat message.
	SIG_NSE_SEND                        // Network size estimate message.
	SIG_GNS_RECORD_SIGN                 // GNS record block.
	SIG_ECC_KEY                         // Set a session key.
	SIG_FS_UBLOCK                       // UBlock Signature, done using DSS, not ECC.
	SIG_REGEX_ACCEPT                    // Accept state (affirm matching service).
	SIG_MULTICAST_MESSAGE               // Multicast message sent by origin.
	SIG_CONVERSATION_RING               // Conversation ring.
	SIG_SECRETSHARING_DKG1              // First round of distributed key generation.
	SIG_SECRETSHARING_DKG2              // Second round of distributed key generation.
	SIG_SECRETSHARING_DECRYPTION        // Cooperative decryption.
	SIG_MULTICAST_REQUEST               // Multicast request sent by member.
	SIG_SENSOR_ANOMALY_REPORT           // Sensor anomaly report message.
	SIG_GNUID_TOKEN                     // GNUid Token.
	SIG_GNUID_TICKET                    // GNUid Ticket.
	SIG_CREDENTIAL                      // GNUnet credential.
)

var (
	ErrSigInvalidPrvKey = fmt.Errorf("Private key not suitable for EdDSA")
	ErrSigIvalidPubKey  = fmt.Errorf("Invalid EcDSA public key data")
	ErrSigNotEdDSA      = fmt.Errorf("Not a EdDSA signature")
	ErrSigNotEcDSA      = fmt.Errorf("Not a EcDSA signature")
	ErrSigInvalidEcDSA  = fmt.Errorf("Invalid EcDSA signature")
)

//----------------------------------------------------------------------
// Signature (EdDSA, EcDSA)
//----------------------------------------------------------------------

// Signature
type Signature struct {
	// internal
	data    []byte
	isEdDSA bool
}

// NewSignatureFromBytes
func NewSignatureFromBytes(data []byte) *Signature {
	return &Signature{
		data: util.Clone(data),
	}
}

// Bytes
func (s *Signature) Bytes() []byte {
	return util.Clone(s.data)
}

//----------------------------------------------------------------------
// EdDSA
//----------------------------------------------------------------------

// Sign creates an EdDSA signature for a message.
func (prv *PrivateKey) Sign(msg []byte) (*Signature, error) {
	if !prv.fromSeed {
		return nil, ErrSigInvalidPrvKey
	}
	hv := sha512.Sum512(msg)
	sig, err := prv.key.Sign(rand.Reader, hv[:], crypto.Hash(0))
	return NewSignatureFromBytes(sig), err
}

// Verify checks an EdDSA signature of a message.
func (pub *PublicKey) Verify(msg []byte, sig *Signature) (bool, error) {
	if !sig.isEdDSA {
		return false, ErrSigNotEdDSA
	}
	hv := sha512.Sum512(msg)
	return ed25519.Verify(pub.key, hv[:], sig.Bytes()), nil
}

//----------------------------------------------------------------------
// EcDSA
//----------------------------------------------------------------------

var (
	n, _ = new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	zero = big.NewInt(0)
)

// SignLin creates an EcDSA signature for a message.
func (prv *PrivateKey) SignLin(msg []byte) (*Signature, error) {
	// Hash message
	hv := sha512.Sum512(msg)
	// compute z
	hv[0] &= 0x3f
	z := new(big.Int).SetBytes(hv[:32])
	// find appropriate k
	for {
		// generate random k
		k, err := rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		k.Mod(k, n)

		// compute x-coordinate of point k*G (stored in buf)
		var (
			q     ed25519.ExtendedGroupElement
			buf   [32]byte
			x, zi ed25519.FieldElement
		)
		copy(buf[:], util.Reverse(k.Bytes()))
		ed25519.GeScalarMultBase(&q, &buf)
		ed25519.FeInvert(&zi, &q.Z)
		ed25519.FeMul(&x, &q.X, &zi)
		ed25519.FeToBytes(&buf, &x)

		// compute non-zero r
		a := new(big.Int).SetBytes(util.Reverse(buf[:]))
		r := new(big.Int).Mod(a, n)
		if r.Cmp(zero) == 0 {
			continue
		}
		r_buf := r.Bytes()

		// compute non-zero s
		ki := new(big.Int).ModInverse(k, n)
		d := prv.D()
		a = new(big.Int).Mul(r, d)
		b := new(big.Int).Add(z, a)
		c := new(big.Int).Mul(ki, b)
		s := new(big.Int).Mod(c, n)
		if s.Cmp(zero) == 0 {
			continue
		}
		s_buf := s.Bytes()
		// assemble signature
		size := len(r_buf) + len(s_buf)
		data := make([]byte, size)
		copy(data, r_buf)
		copy(data[len(r_buf):], s_buf)
		sig := NewSignatureFromBytes(data)
		sig.isEdDSA = false
		return sig, nil
	}
}

// Verify checks a EcDSA signature of a message.
func (pub *PublicKey) VerifyLin(msg []byte, sig *Signature) (bool, error) {
	if sig.isEdDSA {
		return false, ErrSigNotEcDSA
	}
	// reconstruct r and s
	r := new(big.Int).SetBytes(sig.data[:32])
	s := new(big.Int).SetBytes(sig.data[32:])
	// check r,s values
	if r.Cmp(n) != -1 || s.Cmp(n) != -1 {
		return false, ErrSigInvalidEcDSA
	}
	// Hash message
	hv := sha512.Sum512(msg)
	// compute z
	hv[0] &= 0x3f
	z := new(big.Int).SetBytes(hv[:32])
	// compute u1, u2
	si := new(big.Int).ModInverse(s, n)
	b := new(big.Int).Mul(z, si)
	u1 := new(big.Int).Mod(b, n)
	c := new(big.Int).Mul(r, si)
	u2 := new(big.Int).Mod(c, n)
	// compute u2 * Q + u1 * G
	var (
		Q           ed25519.ExtendedGroupElement
		pge         ed25519.ProjectiveGroupElement
		a, u1B, u2B [32]byte
	)
	copy(a[:], pub.Bytes())
	if !Q.FromBytes(&a) {
		return false, ErrSigIvalidPubKey
	}
	copy(u1B[:], util.Reverse(u1.Bytes()))
	copy(u2B[:], util.Reverse(u2.Bytes()))
	ed25519.GeDoubleScalarMultVartime(&pge, &u2B, &Q, &u1B)
	pge.ToBytes(&a)
	x1 := new(big.Int).Mod(NewPublicKey(a[:]).AffineX(), n)
	return r.Cmp(x1) == 0, nil
}
