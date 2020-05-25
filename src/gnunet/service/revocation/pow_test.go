package revocation

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

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
			"uLZSPUmskV8SfAmwtwdw3fl74eBbaIp+35fWignx0FI=",
			"9kuW0t6o4XuBOmhIyZJpyDD092em2eQeM3uWXnJ+ZR0=",
			"AAWl7YHn1XMAAAAAAAAAAE1JXASakruETUlcBJqSv05NSVwEmpK/T01JXASakr+ZTUlcBJqSv6NNSVwEmpK/7U1JXASaksAETUlcBJqSwB9NSVwEmpLAIU1JXASaksCCTUlcBJqSwKpNSVwEmpLBYE1JXASaksGGTUlcBJqSwZxNSVwEmpLB3U1JXASaksIgTUlcBJqSwnVNSVwEmpLCgE1JXASaksM2TUlcBJqSw35NSVwEmpLDhE1JXASaksOqTUlcBJqSw7VNSVwEmpLDuU1JXASaksPXTUlcBJqSxKdNSVwEmpLE3k1JXASaksUTTUlcBJqSxRxNSVwEmpLFXU1JXASaksX/TUlcBJqSxuwHGX4Psd/g2X+D2xl0uli0/RTyVtZ9VfWN5nbw0ij+Cw1Ol+raxEBNIbSuZzVMGsNlBvmunFGhTezUoIaE33DA9kuW0t6o4XuBOmhIyZJpyDD092em2eQeM3uWXnJ+ZR0=",
		},
		{
			"EJJaW7UymipsU6IkFFdt/jkE/kNd22IAyqNb3sMRk2g=",
			"fUBR/J2vCuXXv70BdSi/J0G8n+qxs7LctC34hJaQ7S4=",
			"AAWlWugT9IoAWl4FAQAAAG40PmjcaH+LbjQ+aNxogM1uND5o3GiBPG40PmjcaIKMbjQ+aNxogzhuND5o3GiDvG40PmjcaIPLbjQ+aNxohAFuND5o3GiEVm40PmjcaIRbbjQ+aNxohF1uND5o3GiE2W40PmjcaIV1bjQ+aNxohfluND5o3GiGEG40PmjcaIY1bjQ+aNxohvRuND5o3GiHgW40PmjcaIezbjQ+aNxoiABuND5o3GiIF240PmjcaIgfbjQ+aNxoiD1uND5o3GiIVW40PmjcaIilbjQ+aNxoiLBuND5o3GiIzm40PmjcaIj/bjQ+aNxoiQduND5o3GiJgW40PmjcaIm8bjQ+aNxoidILkGuzZsdbclNZaOXvMPrCO+EHuA6+tacFI1bhURGBowFyaFZjgi3mOOdlKFnkJ0vnauZPIb12C3V6qhoHmhNyfUBR/J2vCuXXv70BdSi/J0G8n+qxs7LctC34hJaQ7S4=",
		},
	}
)

func blob(w *PoWData) []byte {
	blob, err := data.Marshal(w)
	if err != nil {
		return nil
	}
	return blob
}

func TestRevocationRFC(t *testing.T) {

	for _, td := range test_data {
		fmt.Println("---------------------------------")
		skey_d, err := base64.StdEncoding.DecodeString(td.skey)
		if err != nil {
			t.Fatal(err)
		}
		d := math.NewIntFromBytes(skey_d)
		skey := ed25519.NewPrivateKeyFromD(d)
		pkey_d, err := base64.StdEncoding.DecodeString(td.pkey)
		if err != nil {
			t.Fatal(err)
		}
		pkey := ed25519.NewPublicKeyFromBytes(pkey_d)
		if !skey.Public().Q.Equals(pkey.Q) {
			fmt.Println("Private/Public key mismatch")
		}

		rev_d, err := base64.StdEncoding.DecodeString(td.revdata)
		if err != nil {
			t.Fatal(err)
		}

		revData := new(RevData)
		if err = data.Unmarshal(revData, rev_d); err != nil {
			t.Fatal(err)
		}
		work := NewPoWData(0, revData.Timestamp, revData.ZoneKey)
		if testing.Verbose() {
			fmt.Println("REVDATA:")
			fmt.Printf("    Timestamp: %s\n", revData.Timestamp.String())
			fmt.Printf("    TTL: %s\n", revData.TTL.String())
			for i, pow := range revData.PoWs {
				fmt.Printf("    PoW #%d: %d\n", i, pow)
				work.SetPoW(pow)
				buf := blob(work)
				fmt.Printf("        P: %s\n", hex.EncodeToString(buf))
				v := work.Compute()
				fmt.Printf("        H: %s\n", hex.EncodeToString(v.Bytes()))
				num := 512 - v.BitLen()
				fmt.Printf("        --> %d leading zeros\n", num)
			}
			fmt.Printf("    Signature: %s\n", hex.EncodeToString(revData.Signature))
			fmt.Printf("    ZoneKey: %s\n", hex.EncodeToString(revData.ZoneKey))
		}

		rc := revData.Verify(true)
		if testing.Verbose() {
			fmt.Printf("REV_Verify (pkey): %d\n", rc)
		}
	}
}
