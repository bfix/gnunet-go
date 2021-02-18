package revocation

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/math"
)

type testData struct {
	skey    string
	pkey    string
	revdata string
}

var (
	tstData = []testData{
		{

			"90ea2a95cb9ef482b45817dc45b805cae00f387022a065a3674f41ad15173c63", // private scalar D
			"4ac1e51d9a585a9ad9fb0dfac2be100aee83f0cc79c4c5ea8f3eb8afd9092fa5", // public key
			"" +
				"0005a5fd368978f4" + // private scalar D
				"0000395d1827c000" + // public key Ed25519
				"e23f657bc47ec853" + // PoW_0
				"e23f657bc47ec9d8" +
				"e23f657bc47ecaec" +
				"e23f657bc47ecb29" +
				"e23f657bc47ecc00" +
				"e23f657bc47ecc79" +
				"e23f657bc47ece83" +
				"e23f657bc47ecfc6" +
				"e23f657bc47ecfc8" +
				"e23f657bc47ecfd5" +
				"e23f657bc47ed02b" +
				"e23f657bc47ed03b" +
				"e23f657bc47ed0ff" +
				"e23f657bc47ed241" +
				"e23f657bc47ed264" +
				"e23f657bc47ed2e5" +
				"e23f657bc47ed343" +
				"e23f657bc47ed348" +
				"e23f657bc47ed45e" +
				"e23f657bc47ed480" +
				"e23f657bc47ed49a" +
				"e23f657bc47ed564" +
				"e23f657bc47ed565" +
				"e23f657bc47ed5b6" +
				"e23f657bc47ed5de" +
				"e23f657bc47ed5e0" +
				"e23f657bc47ed77f" +
				"e23f657bc47ed800" +
				"e23f657bc47ed80c" +
				"e23f657bc47ed817" +
				"e23f657bc47ed82c" +
				"e23f657bc47ed8a6" + // PoW_31
				"0396020c831a5405cee6c38842209191c8db799dbe81e0dcf6dbd4f91c257ae2" + // Sig.R
				"0079e7fd1cd31cc24cd9a52831d5ec30f10e22e5a6dd906518746cfce2095610" + // Sig.S
				"4ac1e51d9a585a9ad9fb0dfac2be100aee83f0cc79c4c5ea8f3eb8afd9092fa5", // PKEY
		},
	}
)

func TestRevocationRFC(t *testing.T) {

	for i, td := range tstData {
		if testing.Verbose() {
			fmt.Println("---------------------------------")
			fmt.Printf("Test case #%d\n", i+1)
			fmt.Println("---------------------------------")
		}

		// construct private/public key pair from test data
		skeyD, err := hex.DecodeString(td.skey)
		if err != nil {
			t.Fatal(err)
		}
		d := math.NewIntFromBytes(util.Reverse(skeyD))
		skey := ed25519.NewPrivateKeyFromD(d)
		pkeyD, err := hex.DecodeString(td.pkey)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(skey.Public().Bytes(), pkeyD) != 0 {
			t.Fatal("Private/Public key mismatch")
		}

		// assemble revocation data object
		revD, err := hex.DecodeString(td.revdata)
		if err != nil {
			t.Fatal(err)
		}
		revData := new(RevData)
		if err = data.Unmarshal(revData, revD); err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(revData.ZoneKey, pkeyD) != 0 {
			t.Fatal("Wrong zone key in test revocation")
		}

		// show revdata content
		if testing.Verbose() {
			fmt.Println("REVDATA:")
			fmt.Printf("    Timestamp: %s\n", revData.Timestamp.String())
			fmt.Printf("    TTL: %s\n", revData.TTL.String())

			work := NewPoWData(0, revData.Timestamp, revData.ZoneKey)
			for i, pow := range revData.PoWs {
				fmt.Printf("    PoW #%d: %d\n", i, pow)
				work.SetPoW(pow)
				buf := work.Blob()
				fmt.Printf("        P: %s\n", hex.EncodeToString(buf))
				v := work.Compute()
				fmt.Printf("        H: %s\n", hex.EncodeToString(v.Bytes()))
				num := 512 - v.BitLen()
				fmt.Printf("        --> %d leading zeros\n", num)
			}
			fmt.Printf("    Signature: %s\n", hex.EncodeToString(revData.Signature))
			fmt.Printf("    ZoneKey: %s\n", hex.EncodeToString(revData.ZoneKey))
		}

		// verify revocation data object
		rc := revData.Verify(true)
		fmt.Printf("REV_Verify (pkey): %d\n", rc)
	}
}
