package revocation

import (
	"bytes"
	"encoding/hex"
	"gnunet/crypto"
	"gnunet/enums"
	"testing"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/math"
)

// Test revocation with test vector defined in the RFC draft.
func TestRevocationRFC(t *testing.T) {

	var (
		D     = "6fea32c05af58bfa979553d188605fd57d8bf9cc263b78d5f7478c07b998ed70"
		ZKEY  = "000100002ca223e879ecc4bbdeb5da17319281d63b2e3b6955f1c3775c804a98d5f8ddaa"
		DIFF  = 7
		PROOF = "" +
			"0005d6692d2c961d" +
			"0000395d1827c000" +
			"611d2612c23a4e10" +
			"611d2612c23a5281" +
			"611d2612c23a53b5" +
			"611d2612c23a5492" +
			"611d2612c23a54c8" +
			"611d2612c23a5557" +
			"611d2612c23a5569" +
			"611d2612c23a55cb" +
			"611d2612c23a55db" +
			"611d2612c23a55ed" +
			"611d2612c23a560c" +
			"611d2612c23a563c" +
			"611d2612c23a5641" +
			"611d2612c23a565d" +
			"611d2612c23a5671" +
			"611d2612c23a5682" +
			"611d2612c23a56e0" +
			"611d2612c23a56fb" +
			"611d2612c23a570d" +
			"611d2612c23a5722" +
			"611d2612c23a574a" +
			"611d2612c23a57a0" +
			"611d2612c23a57be" +
			"611d2612c23a5817" +
			"611d2612c23a5859" +
			"611d2612c23a585a" +
			"611d2612c23a5887" +
			"611d2612c23a58a0" +
			"611d2612c23a58ad" +
			"611d2612c23a58b8" +
			"611d2612c23a5912" +
			"611d2612c23a5977" +
			"00010000" +
			"2ca223e879ecc4bbdeb5da17319281d63b2e3b6955f1c3775c804a98d5f8ddaa" +
			"0e93d092b597e41282c883d77091cb2b3724a86f6762dbbcd1ae40dd81347ea106444446886cc5acaf9c809dc78eec88177d1f7d382943b1521f61080b7f645f"
		//"099b850835038c1bc05367c089fbc2d1438390e674dfbe3d7b8532dfaa5e14300cbcee7301c634fdbe13dbffd3d672c2782d54020dc0731abc13e66d64264cc4"
	)

	// construct private/public key pair from test data
	skeyD, err := hex.DecodeString(D)
	if err != nil {
		t.Fatal(err)
	}
	d := math.NewIntFromBytes(skeyD)
	skey := ed25519.NewPrivateKeyFromD(d)
	pkeyD, err := hex.DecodeString(ZKEY)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skey.Public().Bytes(), pkeyD[4:]) {
		t.Fatal("Private/Public key mismatch")
	}

	// assemble revocation data object
	revD, err := hex.DecodeString(PROOF)
	if err != nil {
		t.Fatal(err)
	}
	revData := new(RevData)
	if err = data.Unmarshal(revData, revD); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(revData.ZoneKeySig.KeyData, pkeyD[4:]) {
		t.Logf("keydata  = %s\n", hex.EncodeToString(revData.ZoneKeySig.KeyData))
		t.Logf("KEYDATA  = %s\n", hex.EncodeToString(pkeyD[4:]))
		t.Fatal("Wrong zone key in test revocation")
	}

	// show revdata content
	if testing.Verbose() {
		t.Log("REVDATA:")
		t.Logf("    Timestamp: %s\n", revData.Timestamp.String())
		t.Logf("    TTL: %s\n", revData.TTL.String())

		work := NewPoWData(0, revData.Timestamp, &revData.ZoneKeySig.ZoneKey)
		for i, pow := range revData.PoWs {
			t.Logf("    PoW #%d: %d\n", i, pow)
			work.SetPoW(pow)
			buf := work.Blob()
			t.Logf("        P: %s\n", hex.EncodeToString(buf))
			v := work.Compute()
			t.Logf("        H: %s\n", hex.EncodeToString(v.Bytes()))
			num := 512 - v.BitLen()
			t.Logf("        --> %d leading zeros\n", num)
		}
		t.Logf("    ZoneKey: %s\n", hex.EncodeToString(revData.ZoneKeySig.KeyData))
		t.Logf("    Signature: %s\n", hex.EncodeToString(revData.ZoneKeySig.Signature))
	}

	// assemble data for signature
	sigBlock := &SignedRevData{
		Purpose: &crypto.SignaturePurpose{
			Size:    uint32(20 + revData.ZoneKeySig.KeySize()),
			Purpose: enums.SIG_REVOCATION,
		},
		Timestamp: revData.Timestamp,
		ZoneKey:   &revData.ZoneKeySig.ZoneKey,
	}
	sigData, err := data.Marshal(sigBlock)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SigData = %s\n", hex.EncodeToString(sigData))

	sk := crypto.NewZonePrivate(crypto.ZONE_PKEY, skey)
	sigOut, err := crypto.ZoneSign(sigData, sk)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Signature = %s\n", hex.EncodeToString(sigOut.Signature))

	// verify revocation data object
	rc := revData.Verify(true)
	if rc != DIFF {
		t.Fatalf("REV_Verify (pkey): %d\n", rc)
	}
}
