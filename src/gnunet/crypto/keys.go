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

// Error codes
var (
	ErrInvalidPrivateKeyData = fmt.Errorf("Invalid private key data")
)

//----------------------------------------------------------------------
// Public key
//----------------------------------------------------------------------

// PublicKey is a Ed25519 public key.
type PublicKey struct {
	key ed25519.PublicKey
}

// NewPublicKey sets the binary representation of a public key.
// The value is not checked for validity!
func NewPublicKey(data []byte) *PublicKey {
	if l := len(data); l != ed25519.PublicKeySize {
		panic(fmt.Sprintf("NewPublicKey: invalid key size (%d)", l))
	}
	return &PublicKey{
		key: util.Clone(data),
	}
}

// Bytes returns the binary representation of a public key.
func (pub *PublicKey) Bytes() []byte {
	return []byte(pub.key)
}

// Verify checks a signature of a message.
func (pub *PublicKey) Verify(msg []byte, sig *Signature) bool {
	hv := sha512.Sum512(msg)
	return ed25519.Verify(pub.key, hv[:], sig.Bytes())
}

// Mult computes p = d*Q
func (pub *PublicKey) Mult(d *big.Int) *PublicKey {
	var (
		Q          ed25519.ExtendedGroupElement
		pge        ed25519.ProjectiveGroupElement
		a, b, zero [32]byte
	)
	// compute point Q from public key data
	copy(a[:], pub.Bytes())
	if !Q.FromBytes(&a) {
		return nil
	}
	// compute skalar product
	copy(b[:], util.Reverse(d.Bytes()))
	ed25519.GeDoubleScalarMultVartime(&pge, &b, &Q, &zero)

	// convert to public key
	pge.ToBytes(&a)
	return NewPublicKey(a[:])
}

//----------------------------------------------------------------------
// Private Key
//----------------------------------------------------------------------

// PrivateKey is a Ed25519 private key.
type PrivateKey struct {
	key ed25519.PrivateKey // private key data (seed||public_key)
	d   *big.Int           // HACK! "real" private key
}

// PrivateKeyFromSeed returns a private key for a given seed.
func PrivateKeyFromSeed(seed []byte) *PrivateKey {
	k := &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
	// HACK! Save the "real" private key 'd' for later use
	md := sha512.Sum512(seed)
	d := util.Reverse(md[:32])
	d[0] = (d[0] & 0x3f) | 0x40
	d[31] &= 0xf8
	k.d = new(big.Int).SetBytes(d)
	return k
}

// D returns the "real" private key (HACK!)
func (prv *PrivateKey) D() *big.Int {
	return prv.d
}

// Public returns the public key for a private key.
func (prv *PrivateKey) Public() *PublicKey {
	return &PublicKey{
		key: util.Clone(prv.key[ed25519.PublicKeySize:]),
	}
}

// Sign creates a signature for a message.
func (prv *PrivateKey) Sign(msg []byte) (*Signature, error) {
	hv := sha512.Sum512(msg)
	sig, err := prv.key.Sign(rand.Reader, hv[:], crypto.Hash(0))
	return NewSignatureFromBytes(sig), err
}

// NewKeypair creates a new Ed25519 key pair.
func NewKeypair() (*PublicKey, *PrivateKey) {
	seed := make([]byte, 32)
	util.RndArray(seed)
	prv := PrivateKeyFromSeed(seed)
	pub := prv.Public()
	return pub, prv
}

////////////////////////////////////////////////////////////////////////

func DeriveH(pk *PublicKey, label string, context string) *big.Int {
	return nil
}

/*
static gcry_mpi_t
derive_h (const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
          const char *label,
          const char *context)
{
  gcry_mpi_t h;
  struct GNUNET_HashCode hc;
  static const char *const salt = "key-derivation";

  GNUNET_CRYPTO_kdf (&hc,
                     sizeof (hc),
                     salt,
                     strlen (salt),
                     pub,
                     sizeof (*pub),
                     label,
                     strlen (label),
                     context,
                     strlen (context),
                     NULL,
                     0);
  GNUNET_CRYPTO_mpi_scan_unsigned (&h, (unsigned char *) &hc, sizeof (hc));
  return h;
}


func PublicKeyDerive(pkey *PublicKey, label string, context string) *PublicKey {
void
GNUNET_CRYPTO_ecdsa_public_key_derive (
  const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
  const char *label,
  const char *context,
  struct GNUNET_CRYPTO_EcdsaPublicKey *result)
{
  gcry_ctx_t ctx;
  gcry_mpi_t q_y;
  gcry_mpi_t h;
  gcry_mpi_t n;
  gcry_mpi_t h_mod_n;
  gcry_mpi_point_t q;
  gcry_mpi_point_t v;

  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, CURVE));

  /* obtain point 'q' from original public key.  The provided 'q' is
     compressed thus we first store it in the context and then get it
     back as a (decompresssed) point.  *
  q_y = gcry_mpi_set_opaque_copy (NULL, pub->q_y, 8 * sizeof (pub->q_y));
  GNUNET_assert (NULL != q_y);
  GNUNET_assert (0 == gcry_mpi_ec_set_mpi ("q", q_y, ctx));
  gcry_mpi_release (q_y);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);
  GNUNET_assert (q);

  /* calculate h_mod_n = h % n *
  h = derive_h (pub, label, context);
  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  h_mod_n = gcry_mpi_new (256);
  gcry_mpi_mod (h_mod_n, h, n);
  /* calculate v = h_mod_n * q *
  v = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (v, h_mod_n, q, ctx);
  gcry_mpi_release (h_mod_n);
  gcry_mpi_release (h);
  gcry_mpi_release (n);
  gcry_mpi_point_release (q);

  /* convert point 'v' to public key that we return *
  GNUNET_assert (0 == gcry_mpi_ec_set_point ("q", v, ctx));
  gcry_mpi_point_release (v);
  q_y = gcry_mpi_ec_get_mpi ("q@eddsa", ctx, 0);
  GNUNET_assert (q_y);
  GNUNET_CRYPTO_mpi_print_unsigned (result->q_y, sizeof (result->q_y), q_y);
  gcry_mpi_release (q_y);
  gcry_ctx_release (ctx);
}

	return nil
}
*/
