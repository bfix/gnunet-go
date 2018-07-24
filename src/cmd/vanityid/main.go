package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"strings"

	"gnunet/crypto"
	"gnunet/util"
)

func main() {
	flag.Parse()
	prefixes := flag.Args()
	if len(prefixes) == 0 {
		fmt.Println("No prefixes specified -- done.")
		return
	}

	seed := make([]byte, 32)
	for {
		n, err := rand.Read(seed)
		if err != nil || n != 32 {
			panic(err)
		}
		prv := crypto.EdDSAPrivateKeyFromSeed(seed)
		pub := prv.Public().Bytes()
		id := util.EncodeBinaryToString(pub)
		for _, p := range prefixes {
			if strings.HasPrefix(id, p) {
				fmt.Printf("%s [%s]\n", id, hex.EncodeToString(seed))
			}
		}
	}
}
