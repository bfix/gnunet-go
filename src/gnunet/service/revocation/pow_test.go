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
		D     = "70ed98b9078c47f7d5783b26ccf98b7dd55f6088d1539597fa8bf55ac032ea6f"
		ZKEY  = "000100002ca223e879ecc4bbdeb5da17319281d63b2e3b6955f1c3775c804a98d5f8ddaa"
		PROOF = "" +
			"0005d66da3598127" +
			"0000395d1827c000" +
			"3ab877d07570f2b8" +
			"3ab877d07570f332" +
			"3ab877d07570f4f5" +
			"3ab877d07570f50f" +
			"3ab877d07570f537" +
			"3ab877d07570f599" +
			"3ab877d07570f5cd" +
			"3ab877d07570f5d9" +
			"3ab877d07570f66a" +
			"3ab877d07570f69b" +
			"3ab877d07570f72f" +
			"3ab877d07570f7c3" +
			"3ab877d07570f843" +
			"3ab877d07570f8d8" +
			"3ab877d07570f91b" +
			"3ab877d07570f93a" +
			"3ab877d07570f944" +
			"3ab877d07570f98a" +
			"3ab877d07570f9a7" +
			"3ab877d07570f9b0" +
			"3ab877d07570f9df" +
			"3ab877d07570fa05" +
			"3ab877d07570fa3e" +
			"3ab877d07570fa63" +
			"3ab877d07570fa84" +
			"3ab877d07570fa8f" +
			"3ab877d07570fa91" +
			"3ab877d07570fad6" +
			"3ab877d07570fb0a" +
			"3ab877d07570fc0f" +
			"3ab877d07570fc43" +
			"3ab877d07570fca5" +
			"00010000" +
			"2ca223e879ecc4bbdeb5da17319281d63b2e3b6955f1c3775c804a98d5f8ddaa" +
			"053b0259700039187d1da4613531502bc4a4eeccc69900d24f8aac5430f28fc5092701331f178e290fe06e82ce2498ce7b23a34058e3d6a2f247e92bc9d7b9ab"
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
