// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
//
// gnunet-go is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// gnunet-go is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"gnunet/service/revocation"
	"gnunet/util"

	"github.com/bfix/gospel/data"
)

func main() {
	log.Println("*** Compute revocation data for a zone key")
	log.Println("*** Copyright (c) 2020, Bernd Fix  >Y<")
	log.Println("*** This is free software distributed under the Affero GPL v3.")

	// handle command line arguments
	var (
		verbose  bool   // be verbose with messages
		bits     int    // number of leading zero-bit requested
		zonekey  string // zonekey to be revoked
		filename string // name of file for persistance
	)
	flag.IntVar(&bits, "b", 25, "Number of leading zero bits")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.StringVar(&zonekey, "z", "", "Zone key to be revoked")
	flag.StringVar(&filename, "f", "", "Name of file to store revocation")
	flag.Parse()

	if len(filename) == 0 {
		log.Fatal("Missing '-f' argument (filename fot revocation data)")
	}

	// define layout of persistant data
	var revData struct {
		Rd      *revocation.RevDataCalc // Revocation data
		T       util.RelativeTime       // time spend in calculations
		Last    uint64                  // last value used for PoW test
		Numbits uint8                   // number of leading zero-bits
	}
	dataBuf := make([]byte, 450)

	// read revocation object from file
	file, err := os.Open(filename)
	cont := true
	if err != nil {
		if len(zonekey) != 52 {
			log.Fatal("Missing or invalid zonekey and no file specified -- aborting")
		}
		keyData, err := util.DecodeStringToBinary(zonekey, 32)
		if err != nil {
			log.Fatal("Invalid zonekey: " + err.Error())
		}
		revData.Rd = revocation.NewRevDataCalc(keyData)
		revData.Numbits = uint8(bits)
		revData.T = util.NewRelativeTime(0)
		cont = false
	} else {
		n, err := file.Read(dataBuf)
		if err != nil {
			log.Fatal("Error reading file: " + err.Error())
		}
		if n != len(dataBuf) {
			log.Fatal("File corrupted -- aborting")
		}
		if err = data.Unmarshal(&revData, dataBuf); err != nil {
			log.Fatal("File corrupted: " + err.Error())
		}
		bits = int(revData.Numbits)
		if err = file.Close(); err != nil {
			log.Fatal("Error closing file: " + err.Error())
		}
	}

	if cont {
		log.Printf("Revocation calculation started at %s\n", revData.Rd.Timestamp.String())
		log.Printf("Time spent on calculation: %s\n", revData.T.String())
		log.Printf("Last tested PoW value: %d\n", revData.Last)
		log.Println("Continuing...")
	} else {
		log.Println("Starting new revocation calculation...")
	}
	log.Println("Press ^C to abort...")

	// pre-set difficulty
	log.Printf("Difficulty: %d\n", bits)
	if bits < 25 {
		log.Println("WARNING: difficulty is less than 25!")
	}

	// Start or continue calculation
	ctx, cancelFcn := context.WithCancel(context.Background())
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		cb := func(average float64, last uint64) {
			log.Printf("Improved PoW: %f average zero bits, %d steps\n", average, last)
		}

		startTime := util.AbsoluteTimeNow()
		average, last := revData.Rd.Compute(ctx, bits, revData.Last, cb)
		if average < float64(bits) {
			log.Printf("Incomplete revocation: Only %f zero bits on average!\n", average)
		} else {
			log.Println("Revocation data object:")
			log.Println("   0x" + hex.EncodeToString(revData.Rd.Blob()))
			log.Println("Status:")
			rc := revData.Rd.Verify(false)
			switch {
			case rc == -1:
				log.Println("    Missing/invalid signature")
			case rc == -2:
				log.Println("    Expired revocation")
			case rc == -3:
				log.Println("    Wrong PoW sequence order")
			case rc < 25:
				log.Println("    Difficulty to small")
			default:
				log.Printf("    Difficulty: %d\n", rc)
			}
		}
		if !cont || last != revData.Last {
			revData.Last = last
			revData.T = util.AbsoluteTimeNow().Diff(startTime)

			log.Println("Writing revocation data to file...")
			file, err := os.Create(filename)
			if err != nil {
				log.Fatal("Can't write to output file: " + err.Error())
			}
			buf, err := data.Marshal(&revData)
			if err != nil {
				log.Fatal("Internal error: " + err.Error())
			}
			if len(buf) != len(dataBuf) {
				log.Fatalf("Internal error: Buffer mismatch %d != %d", len(buf), len(dataBuf))
			}
			n, err := file.Write(buf)
			if err != nil {
				log.Fatal("Can't write to output file: " + err.Error())
			}
			if n != len(dataBuf) {
				log.Fatal("Can't write data to output file!")
			}
			if err = file.Close(); err != nil {
				log.Fatal("Error closing file: " + err.Error())
			}
		}
	}()

	go func() {
		// handle OS signals
		sigCh := make(chan os.Signal, 5)
		signal.Notify(sigCh)
	loop:
		for {
			select {
			// handle OS signals
			case sig := <-sigCh:
				switch sig {
				case syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM:
					log.Printf("Terminating (on signal '%s')\n", sig)
					cancelFcn()
					break loop
				case syscall.SIGHUP:
					log.Println("SIGHUP")
				case syscall.SIGURG:
					// TODO: https://github.com/golang/go/issues/37942
				default:
					log.Println("Unhandled signal: " + sig.String())
				}
			}
		}
	}()
	wg.Wait()
}
