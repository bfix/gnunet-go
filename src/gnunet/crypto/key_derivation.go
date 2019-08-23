package crypto

import ()

////////////////////////////////////////////////////////////////////////

func (pub *PublicKey) Derive(label string, context string) *PublicKey {
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
