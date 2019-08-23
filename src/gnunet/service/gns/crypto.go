package gns

import (
//	"gnunet/crypto"
)

/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 *
 * @param pub public key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 *
void
GNUNET_GNSRECORD_query_from_public_key (const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
					const char *label,
					struct GNUNET_HashCode *query)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pd;

  GNUNET_CRYPTO_ecdsa_public_key_derive (pub,
                                         label,
                                         "gns",
                                         &pd);
  GNUNET_CRYPTO_hash (&pd,
                      sizeof (pd),
                      query);
}


// QueryFromPublickeyDerive
func QueryFromPublickeyDerive(pkey *crypto.PublicKey, label string) *crypto.HashCode {
	pd := crypto.PublicKeyDerive(pkey, label, "gns")
	return crypto.Hash(pd.Bytes())
}
*/
