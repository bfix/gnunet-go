package main

import (
	"flag"
	"fmt"
	"log"

	"gnunet/service/revocation"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/math"
)

func main() {
	var (
		quiet bool
		bits  int
	)
	flag.IntVar(&bits, "b", 25, "Number of leading zero bits")
	flag.BoolVar(&quiet, "q", false, "Be quiet")
	flag.Parse()
	fmt.Printf("Leading zeros required: %d\n", bits)

	// generate a random key pair
	pkey, _ := ed25519.NewKeypair()

	// initialize RevData structure
	rd := revocation.NewRevData(0, pkey)

	// pre-set difficulty
	difficulty := math.TWO.Pow(512 - bits).Sub(math.ONE)

	var count uint64 = 0
	for {
		result, err := rd.Compute()
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Printf("Nonce=%d, Result=(%d) %v\n", rd.GetNonce(), result.BitLen(), result)
		if result.Cmp(difficulty) < 0 {
			break
		}
		count++
		rd.Next()
	}
	fmt.Printf("PoW found after %d iterations:\n", count)
	fmt.Printf("--> Nonce=%d\n", rd.GetNonce())
}
