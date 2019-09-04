package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"regexp"

	"gnunet/crypto"
	"gnunet/util"
)

func main() {
	// get arguments
	flag.Parse()
	prefixes := flag.Args()
	num := len(prefixes)
	if num == 0 {
		fmt.Println("No prefixes specified -- done.")
		return
	}

	// pre-compile regexp
	reg := make([]*regexp.Regexp, num)
	for i, p := range prefixes {
		reg[i] = regexp.MustCompile(p)
	}

	// generate new keys in a loop
	seed := make([]byte, 32)
	for {
		n, err := rand.Read(seed)
		if err != nil || n != 32 {
			panic(err)
		}
		prv := crypto.NewPrivateKeyFromSeed(seed)
		pub := prv.Public().Bytes()
		id := util.EncodeBinaryToString(pub)
		for _, r := range reg {
			if r.MatchString(id) {
				fmt.Printf("%s [%s]\n", id, hex.EncodeToString(seed))
			}
		}
	}
}
