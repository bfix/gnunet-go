package revocation

import (
	"bytes"
	"encoding/hex"
	"gnunet/crypto"
	"gnunet/enums"
	"testing"

	"github.com/bfix/gospel/data"
)

// Test revocation with test vector defined in the RFC draft.
func TestRevocationRFC(t *testing.T) {
	var (
		D     = "6fea32c05af58bfa979553d188605fd57d8bf9cc263b78d5f7478c07b998ed70"
		ZKEY  = "000100002ca223e879ecc4bbdeb5da17319281d63b2e3b6955f1c3775c804a98d5f8ddaa"
		PROOF = "" +
			"0005feb46d865c1c" +
			"0000395d1827c000" +
			"e66a570bccd4b393" +
			"e66a570bccd4b3ea" +
			"e66a570bccd4b536" +
			"e66a570bccd4b542" +
			"e66a570bccd4b613" +
			"e66a570bccd4b65f" +
			"e66a570bccd4b672" +
			"e66a570bccd4b70a" +
			"e66a570bccd4b71a" +
			"e66a570bccd4b723" +
			"e66a570bccd4b747" +
			"e66a570bccd4b777" +
			"e66a570bccd4b785" +
			"e66a570bccd4b789" +
			"e66a570bccd4b7cf" +
			"e66a570bccd4b7dc" +
			"e66a570bccd4b93a" +
			"e66a570bccd4b956" +
			"e66a570bccd4ba4a" +
			"e66a570bccd4ba9d" +
			"e66a570bccd4bb28" +
			"e66a570bccd4bb5a" +
			"e66a570bccd4bb92" +
			"e66a570bccd4bba2" +
			"e66a570bccd4bbd8" +
			"e66a570bccd4bbe2" +
			"e66a570bccd4bc93" +
			"e66a570bccd4bc94" +
			"e66a570bccd4bd0f" +
			"e66a570bccd4bdce" +
			"e66a570bccd4be6a" +
			"e66a570bccd4be73" +
			"00010000" +
			"2ca223e879ecc4bbdeb5da17319281d63b2e3b6955f1c3775c804a98d5f8ddaa" +
			"044a878a158b40f0c841d9f978cb1372eaee5199a3d87e5e2bdbc72a6c8c73d0" +
			"00181dfc39c3aaa481667b165b5844e450713d8ab6a3b2ba8fef447b65076a0f"
	)

	// construct private/public key pair from test data
	d, err := hex.DecodeString(D)
	if err != nil {
		t.Fatal(err)
	}
	prv, err := crypto.NewZonePrivate(enums.GNS_TYPE_PKEY, d)
	if err != nil {
		t.Fatal(err)
	}
	zk := prv.Public()

	// check
	zkey, err := hex.DecodeString(ZKEY)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(zk.Bytes(), zkey) {
		t.Logf("zkey = %s\n", hex.EncodeToString(zk.Bytes()))
		t.Logf("ZKEY = %s\n", hex.EncodeToString(zkey))
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
	if err = revData.ZoneKeySig.Init(); err != nil {
		t.Fatal(err)
	}
	// check sigature
	if !bytes.Equal(revData.ZoneKeySig.ZoneKey.Bytes(), zkey) {
		t.Logf("zkey  = %s\n", hex.EncodeToString(revData.ZoneKeySig.Bytes()))
		t.Logf("ZKEY  = %s\n", hex.EncodeToString(zkey))
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
	if testing.Verbose() {
		t.Logf("SigData = %s\n", hex.EncodeToString(sigData))
	}

	sigOut, err := prv.Sign(sigData)
	if err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		t.Logf("Signature = %s\n", hex.EncodeToString(sigOut.Signature))
		t.Logf("         ?= %s\n", hex.EncodeToString(revData.ZoneKeySig.Signature))
	}

	// verify revocation data object
	diff, rc := revData.Verify(true)
	if testing.Verbose() {
		t.Logf("Average difficulty of PoWs = %f\n", diff)
	}
	if rc != 0 {
		t.Fatalf("REV_Verify (pkey): %d\n", rc)
	}
}
