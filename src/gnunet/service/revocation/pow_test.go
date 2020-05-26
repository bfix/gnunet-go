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
	test_data = []testData{
		{

			"e01d304d45676849edcb36c843ad31837c9de8c7e58028a2e7c2a9894f130b6f", // private scalar D
			"d2c825295cfd3073b6149c4393aa9483c51cfaf62731d2bf1127856913233b78", // public key
			"" +
				"0005a5fc192e1d2c" + // timestamp
				"0000395d1827c000" + // TTL
				"f74d39f9ee9a7344" + // PoW_0
				"f74d39f9ee9a7610" +
				"f74d39f9ee9a7677" +
				"f74d39f9ee9a7774" +
				"f74d39f9ee9a777d" +
				"f74d39f9ee9a77a3" +
				"f74d39f9ee9a77ad" +
				"f74d39f9ee9a77b9" +
				"f74d39f9ee9a77de" +
				"f74d39f9ee9a7851" +
				"f74d39f9ee9a786f" +
				"f74d39f9ee9a78a3" +
				"f74d39f9ee9a78ba" +
				"f74d39f9ee9a78ca" +
				"f74d39f9ee9a7916" +
				"f74d39f9ee9a79a9" +
				"f74d39f9ee9a7a37" +
				"f74d39f9ee9a7a57" +
				"f74d39f9ee9a7a5c" +
				"f74d39f9ee9a7a9e" +
				"f74d39f9ee9a7ad3" +
				"f74d39f9ee9a7b1b" +
				"f74d39f9ee9a7b7b" +
				"f74d39f9ee9a7b83" +
				"f74d39f9ee9a7b8b" +
				"f74d39f9ee9a7bbe" +
				"f74d39f9ee9a7bcc" +
				"f74d39f9ee9a7be6" +
				"f74d39f9ee9a7c2b" +
				"f74d39f9ee9a7c5b" +
				"f74d39f9ee9a7c5f" +
				"f74d39f9ee9a7c83" + // PoW_31
				"05b94e2ad6496a8938aaf122f91edbacf2401cce8ec02e551e2a4433e0a76256" + // Sig.R
				"09195bbe7636e9fd9076f8f20bc62467cc8371c487e7809efeaeb6ef7178b623" + // Sig.S
				"d2c825295cfd3073b6149c4393aa9483c51cfaf62731d2bf1127856913233b78", // PKEY
		},
	}
)

func TestRevocationRFC(t *testing.T) {

	for i, td := range test_data {
		if testing.Verbose() {
			fmt.Println("---------------------------------")
			fmt.Printf("Test case #%d\n", i+1)
			fmt.Println("---------------------------------")
		}

		// construct private/public key pair from test data
		skey_d, err := hex.DecodeString(td.skey)
		if err != nil {
			t.Fatal(err)
		}
		d := math.NewIntFromBytes(util.Reverse(skey_d))
		skey := ed25519.NewPrivateKeyFromD(d)
		pkey_d, err := hex.DecodeString(td.pkey)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(skey.Public().Bytes(), pkey_d) != 0 {
			t.Fatal("Private/Public key mismatch")
		}

		// assemble revocation data object
		rev_d, err := hex.DecodeString(td.revdata)
		if err != nil {
			t.Fatal(err)
		}
		revData := new(RevData)
		if err = data.Unmarshal(revData, rev_d); err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(revData.ZoneKey, pkey_d) != 0 {
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
