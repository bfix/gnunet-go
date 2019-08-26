package crypto

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
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
	ErrSigHashTooSmall  = fmt.Errorf("Hash value to small")
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
// EcDSA (classic or deterministic; see RFC 6979)
//----------------------------------------------------------------------

// dsa_get_bounded constructs an integer of order 'n' from binary data (message hash).
func dsa_get_bounded(data []byte) *big.Int {
	z := new(big.Int).SetBytes(data)
	bits := len(data)*8 - ED25519_BITS
	if bits > 0 {
		z.Rsh(z, uint(bits))
	}
	return z
}

//----------------------------------------------------------------------
// kGenerator is an interface for standard or deterministic computation of the
// blinding factor 'k' in an EcDSA signature. It always uses SHA512 as a
// hashing algorithm.
type kGenerator interface {
	init(x *big.Int, h1 []byte) error
	next() (*big.Int, error)
}

// newKGenerator creates a new suitable generator for the binding factor 'k'.
func newKGenerator(det bool, x *big.Int, h1 []byte) (gen kGenerator, err error) {
	if det {
		gen = &kGenDet{}
	} else {
		gen = &kGenStd{}
	}
	err = gen.init(x, h1)
	return
}

//----------------------------------------------------------------------
// kGenDet is a RFC6979-compliant generator.
type kGenDet struct {
	x    *big.Int
	V, K []byte
	hmac hash.Hash
}

// init prepares a generator
func (k *kGenDet) init(x *big.Int, h1 []byte) error {
	// enforce 512 bit hash value (SHA512)
	if len(h1) != 64 {
		return ErrSigHashTooSmall
	}

	// initialize generator specs
	k.x = x
	k.hmac = hmac.New(sha512.New, x.Bytes())

	// initialize hmac'd data
	// data = int2octets(key) || bits2octets(hash)
	data := make([]byte, 128)
	util.CopyBlock(data[0:64], x.Bytes())
	util.CopyBlock(data[64:128], h1)

	k.V = bytes.Repeat([]byte{0x01}, 64)
	k.K = bytes.Repeat([]byte{0x00}, 64)

	// start sequence for 'V' and 'K':
	// (1) K = HMAC_K(V || 0x00 || data)
	k.hmac.Reset()
	k.hmac.Write(k.V)
	k.hmac.Write([]byte{0x00})
	k.hmac.Write(data)
	k.K = k.hmac.Sum(nil)
	// (2) V = HMAC_K(V)
	k.hmac.Reset()
	k.hmac.Write(k.V)
	k.V = k.hmac.Sum(nil)
	// (3) K = HMAC_K(V || 0x01 || data)
	k.hmac.Reset()
	k.hmac.Write(k.V)
	k.hmac.Write([]byte{0x01})
	k.hmac.Write(data)
	k.K = k.hmac.Sum(nil)
	// (4) V = HMAC_K(V)
	k.hmac.Reset()
	k.hmac.Write(k.V)
	k.V = k.hmac.Sum(nil)

	return nil
}

// next returns the next 'k'
func (k *kGenDet) next() (*big.Int, error) {
	k.hmac.Reset()
	k.hmac.Write(k.V)
	k.V = k.hmac.Sum(nil)

	// extract 'k' from data
	kRes := dsa_get_bounded(k.V)

	// prepare for possible next round
	// (1) K = HMAC_K(V || 0x00
	k.hmac.Reset()
	k.hmac.Write(k.V)
	k.hmac.Write([]byte{0x00})
	k.K = k.hmac.Sum(nil)
	// (2) V = HMAC_K(V)
	k.hmac.Reset()
	k.hmac.Write(k.V)
	k.V = k.hmac.Sum(nil)

	return kRes, nil
}

//----------------------------------------------------------------------
// kGenStd is a random generator.
type kGenStd struct {
}

// init prepares a generator
func (k *kGenStd) init(x *big.Int, h1 []byte) error {
	return nil
}

// next returns the next 'k'
func (*kGenStd) next() (*big.Int, error) {
	// generate random k
	return rand.Int(rand.Reader, ED25519_N)
}

//----------------------------------------------------------------------
// SignLin creates an EcDSA signature for a message.
func (prv *PrivateKey) SignLin(msg []byte) (*Signature, error) {
	// Hash message
	hv := sha512.Sum512(msg)

	// compute z
	z := dsa_get_bounded(hv[:])

	// dsa_sign creates a signature. A deterministic signature implements RFC6979.
	dsa_sign := func(det bool) (r, s *big.Int, err error) {
		zero := big.NewInt(0)
		gen, err := newKGenerator(det, prv.D(), hv[:])
		if err != nil {
			return nil, nil, err
		}
		for {
			// generate next possible 'k'
			k, err := gen.next()
			if err != nil {
				return nil, nil, err
			}

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
			r := new(big.Int).Mod(a, ED25519_N)
			if r.Cmp(zero) == 0 {
				continue
			}

			// compute non-zero s
			ki := new(big.Int).ModInverse(k, ED25519_N)
			d := prv.D()
			a = new(big.Int).Mul(r, d)
			b := new(big.Int).Add(z, a)
			c := new(big.Int).Mul(ki, b)
			s := new(big.Int).Mod(c, ED25519_N)
			if s.Cmp(zero) == 0 {
				continue
			}
			return r, s, nil
		}
	}

	// assemble signature
	r, s, err := dsa_sign(true)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 64)
	util.CopyBlock(data[0:32], r.Bytes())
	util.CopyBlock(data[32:64], s.Bytes())
	sig := NewSignatureFromBytes(data)
	sig.isEdDSA = false
	return sig, nil
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
	if r.Cmp(ED25519_N) != -1 || s.Cmp(ED25519_N) != -1 {
		return false, ErrSigInvalidEcDSA
	}
	// Hash message
	hv := sha512.Sum512(msg)
	// compute z
	z := dsa_get_bounded(hv[:])
	// compute u1, u2
	si := new(big.Int).ModInverse(s, ED25519_N)
	b := new(big.Int).Mul(z, si)
	u1 := new(big.Int).Mod(b, ED25519_N)
	c := new(big.Int).Mul(r, si)
	u2 := new(big.Int).Mod(c, ED25519_N)
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
	x1 := new(big.Int).Mod(NewPublicKey(a[:]).AffineX(), ED25519_N)
	return r.Cmp(x1) == 0, nil
}
