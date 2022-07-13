package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"regexp"
	"time"

	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
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
	start := time.Now()
	for i := 0; ; i++ {
		_, _ = rand.Read(seed)
		prv := ed25519.NewPrivateKeyFromSeed(seed)
		pub := prv.Public().Bytes()
		id := util.EncodeBinaryToString(pub)
		for _, r := range reg {
			if r.MatchString(id) {
				elapsed := time.Since(start)
				s1 := hex.EncodeToString(seed)
				s2 := hex.EncodeToString(prv.D.Bytes())
				fmt.Printf("%s [%s][%s] (%d tries, %s elapsed)\n", id, s1, s2, i, elapsed)
				i = 0
				start = time.Now()
			}
		}
	}
}
