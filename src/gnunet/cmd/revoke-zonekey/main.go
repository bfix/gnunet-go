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
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"gnunet/crypto"
	"gnunet/service/revocation"
	"gnunet/util"

	"github.com/bfix/gospel/data"
)

//----------------------------------------------------------------------
// Data structure used to calculate a valid revocation for a given
// zone key.
//----------------------------------------------------------------------

// State of RevData calculation
const (
	S_NEW    = iota // start new PoW calculation
	S_CONT          // continue PoW calculation
	S_DONE          // PoW calculation done
	S_SIGNED        // revocation data signed
)

// RevData is the storage layout for persistent data used by this program.
// Data is read from and written to a file
type RevData struct {
	Rd      *revocation.RevDataCalc ``            // Revocation data
	T       util.RelativeTime       ``            // time spend in calculations
	Last    uint64                  `order:"big"` // last value used for PoW test
	Numbits uint8                   ``            // number of leading zero-bits (difficulty)
	State   uint8                   ``            // processing state
}

// ReadRevData restores revocation data from perstistent storage. If no
// stored data is found, a new revocation data structure is returned.
func ReadRevData(filename string, bits int, zk *crypto.ZoneKey) (rd *RevData, err error) {
	// create new initialized revocation instance with no PoWs.
	rd = &RevData{
		Rd:      revocation.NewRevDataCalc(zk),
		Numbits: uint8(bits),
		T:       util.NewRelativeTime(0),
		State:   S_NEW,
	}

	// read revocation object from file. If the file does not exist, a new
	// calculation is started; otherwise the old calculation will continue.
	var file *os.File
	if file, err = os.Open(filename); err != nil {
		return
	}
	// read existing file
	dataBuf := make([]byte, rd.size())
	var n int
	if n, err = file.Read(dataBuf); err != nil {
		err = fmt.Errorf("Error reading file: " + err.Error())
		return
	}
	if n != len(dataBuf) {
		err = fmt.Errorf("File size mismatch")
		return
	}
	if err = data.Unmarshal(&rd, dataBuf); err != nil {
		err = fmt.Errorf("File corrupted: " + err.Error())
		return
	}
	if !zk.Equal(&rd.Rd.RevData.ZoneKeySig.ZoneKey) {
		err = fmt.Errorf("Zone key mismatch")
		return
	}
	bits = int(rd.Numbits)
	if err = file.Close(); err != nil {
		err = fmt.Errorf("Error closing file: " + err.Error())
	}
	return
}

// Write revocation data to file
func (r *RevData) Write(filename string) (err error) {
	var file *os.File
	if file, err = os.Create(filename); err != nil {
		return fmt.Errorf("Can't write to output file: " + err.Error())
	}
	var buf []byte
	if buf, err = data.Marshal(r); err != nil {
		return fmt.Errorf("Internal error: " + err.Error())
	}
	if len(buf) != r.size() {
		return fmt.Errorf("Internal error: Buffer mismatch %d != %d", len(buf), r.size())
	}
	var n int
	if n, err = file.Write(buf); err != nil {
		return fmt.Errorf("Can't write to output file: " + err.Error())
	}
	if n != len(buf) {
		return fmt.Errorf("Can't write data to output file!")
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("Error closing file: " + err.Error())
	}
	return
}

// size of the RevData instance in bytes.
func (r *RevData) size() int {
	return 18 + r.Rd.Size()
}

// revoke-zonekey generates a revocation message in a multi-step/multi-state
// process run stand-alone from other GNUnet services:
//
// (1) Generate the desired PoWs for the public zone key:
//     This process can be started, stopped and resumed, so the long
//     calculation time (usually days or even weeks) can be interruped if
//     desired. For security reasons you should only pass the "-z" argument to
//     this step but not the "-k" argument (private key) as it is not required
//     to calculate the PoWs.
//
//
// (2) A fully generated PoW set can be signed with the private key to create
//     the final revocation data to be send out. This requires to pass the "-k"
//     and "-z" argument.
//
// The two steps can be run (sequentially) on separate machines; step one requires
// computing power nd memory and step two requires a trusted environment.
func main() {
	log.Println("*** Compute revocation data for a zone key")
	log.Println("*** Copyright (c) 2020-2022, Bernd Fix  >Y<")
	log.Println("*** This is free software distributed under the Affero GPL v3.")

	//------------------------------------------------------------------
	// handle command line arguments
	//------------------------------------------------------------------
	var (
		verbose  bool   // be verbose with messages
		bits     int    // number of leading zero-bit requested
		zonekey  string // zonekey to be revoked
		prvkey   string // private zonekey (base64-encoded key data)
		testing  bool   // test mode (no minimum difficulty)
		filename string // name of file for persistance
	)
	minDiff := revocation.MinDifficulty
	flag.IntVar(&bits, "b", minDiff+1, "Number of leading zero bits")
	flag.StringVar(&zonekey, "z", "", "Zone key to be revoked (zone ID)")
	flag.StringVar(&prvkey, "k", "", "Private zone key (base54-encoded)")
	flag.StringVar(&filename, "f", "", "Name of file to store revocation")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.BoolVar(&testing, "t", false, "test-mode only")
	flag.Parse()

	// check arguments (difficulty, zonekey and filename)
	if bits < minDiff {
		if testing {
			log.Printf("WARNING: difficulty is less than %d!", minDiff)
		} else {
			log.Printf("INFO: difficulty set to %d (required minimum)", minDiff)
			bits = minDiff
		}
	}
	if len(filename) == 0 {
		log.Fatal("Missing '-f' argument (filename for revocation data)")
	}

	//------------------------------------------------------------------
	// Handle zone keys.
	//------------------------------------------------------------------
	var (
		keyData []byte              // binary key data
		zk      *crypto.ZoneKey     // GNUnet zone key
		sk      *crypto.ZonePrivate // GNUnet private zone key
		err     error
	)
	// reconstruct public key
	if keyData, err = util.DecodeStringToBinary(zonekey, 32); err != nil {
		log.Fatal("Invalid zonekey encoding: " + err.Error())
	}
	if zk, err = crypto.NewZoneKey(keyData); err != nil {
		log.Fatal("Invalid zonekey format: " + err.Error())
	}
	// reconstruct private key (optional)
	if len(prvkey) > 0 {
		if keyData, err = base64.StdEncoding.DecodeString(prvkey); err != nil {
			log.Fatal("Invalid private zonekey encoding: " + err.Error())
		}
		if sk, err = crypto.NewZonePrivate(zk.Type, keyData); err != nil {
			log.Fatal("Invalid zonekey format: " + err.Error())
		}
		// verify consistency
		if !zk.Equal(sk.Public()) {
			log.Fatal("Public and private zone keys don't match.")
		}
	}

	//------------------------------------------------------------------
	// Read revocation data from file to continue calculation or to sign
	// the revocation. If no file exists, a new (empty) instance is
	// returned.
	//------------------------------------------------------------------
	rd, err := ReadRevData(filename, bits, zk)

	// handle revocation data state
	switch rd.State {
	case S_NEW:
		log.Println("Starting new revocation calculation...")
		rd.State = S_CONT

	case S_CONT:
		log.Printf("Revocation calculation started at %s\n", rd.Rd.Timestamp.String())
		log.Printf("Time spent on calculation: %s\n", rd.T.String())
		log.Printf("Last tested PoW value: %d\n", rd.Last)
		log.Println("Continuing...")

	case S_DONE:
		// calculation complete: sign with private key
		if sk == nil {
			log.Fatal("Need to sign revocation: private key is missing.")
		}
		log.Println("Signing revocation with private key")
		if err := rd.Rd.Sign(sk); err != nil {
			log.Fatal("Failed to sign revocation: " + err.Error())
		}
		// write final revocation
		rd.State = S_SIGNED
		if err = rd.Write(filename); err != nil {
			log.Fatal("Failed to write revocation: " + err.Error())
		}
		log.Println("Revocation complete and ready for (later) use.")
		return
	}
	// Continue (or start) calculation
	log.Println("Press ^C to abort...")
	log.Printf("Difficulty: %d\n", bits)

	ctx, cancelFcn := context.WithCancel(context.Background())
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// show progress messages
		cb := func(average float64, last uint64) {
			log.Printf("Improved PoW: %.2f average zero bits, %d steps\n", average, last)
		}

		// calculate revocation data until the required difficulty is met
		// or the process is terminated by the user (by pressing ^C).
		startTime := util.AbsoluteTimeNow()
		average, last := rd.Rd.Compute(ctx, bits, rd.Last, cb)

		// check achieved diffiulty (average)
		if average < float64(bits) {
			// The calculation was interrupted; we still need to compute
			// more and better PoWs...
			log.Printf("Incomplete revocation: Only %f zero bits on average!\n", average)
			rd.State = S_CONT
		} else {
			// we have reached the required PoW difficulty
			rd.State = S_DONE
			// check if we have a valid revocation.
			log.Println("Revocation calculation complete:")
			diff, rc := rd.Rd.Verify(false)
			switch {
			case rc == -1:
				log.Println("    Missing/invalid signature")
			case rc == -2:
				log.Println("    Expired revocation")
			case rc == -3:
				log.Println("    Wrong PoW sequence order")
			case diff < float64(revocation.MinAvgDifficulty):
				log.Println("    Difficulty to small")
			default:
				log.Printf("    Difficulty is %.2f\n", diff)
			}
		}
		// update elapsed time
		rd.T.Add(util.AbsoluteTimeNow().Diff(startTime))
		rd.Last = last

		log.Println("Writing revocation data to file...")
		if err = rd.Write(filename); err != nil {
			log.Fatal("Can't write to file: " + err.Error())
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
