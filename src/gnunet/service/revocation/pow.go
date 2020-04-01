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

package revocation

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"sync"

	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/math"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/twofish"
)

//----------------------------------------------------------------------
// Revocation data
//----------------------------------------------------------------------

// RevData is the revocation data structure (wire format)
type RevData struct {
	Nonce   uint64 `order:"big"` // start with this nonce value
	ZoneKey []byte `size:"32"`   // public zone key to be revoked

	// transient attributes (not serialized)
	blob []byte // binary representation of serialized data
}

// NewRevData creates a RevData instance for the given arguments.
func NewRevData(nonce uint64, zoneKey *ed25519.PublicKey) *RevData {
	rd := &RevData{
		Nonce:   nonce,
		ZoneKey: make([]byte, 32),
	}
	copy(rd.ZoneKey, zoneKey.Bytes())
	blob, err := data.Marshal(rd)
	if err != nil {
		return nil
	}
	rd.blob = blob
	return rd
}

// GetNonce returns the last checked nonce value
func (r *RevData) GetNonce() uint64 {
	if r.blob != nil {
		var val uint64
		binary.Read(bytes.NewReader(r.blob[:8]), binary.BigEndian, &val)
		r.Nonce = val
	}
	return r.Nonce
}

// GetBlob returns the binary representation of RevData
func (r *RevData) GetBlob() []byte {
	return r.blob
}

// Next selects the next nonce to be tested.
func (r *RevData) Next() {
	var incr func(pos int)
	incr = func(pos int) {
		r.blob[pos]++
		if r.blob[pos] != 0 || pos == 0 {
			return
		}
		incr(pos - 1)
	}
	incr(7)
}

// Compute calculates the current result for a RevData content.
// The result is returned as a big integer value.
func (r *RevData) Compute() (*math.Int, error) {

	// generate key material
	k, err := scrypt.Key(r.blob, []byte("gnunet-revocation-proof-of-work"), 2, 8, 2, 32)
	if err != nil {
		return nil, err
	}

	// generate initialization vector
	iv := make([]byte, 16)
	prk := hkdf.Extract(sha512.New, k, []byte("gnunet-proof-of-work-iv"))
	rdr := hkdf.Expand(sha256.New, prk, []byte("gnunet-revocation-proof-of-work"))
	rdr.Read(iv)

	// Encrypt with Twofish CFB stream cipher
	out := make([]byte, len(r.blob))
	tf, err := twofish.NewCipher(k)
	if err != nil {
		return nil, err
	}
	cipher.NewCFBEncrypter(tf, iv).XORKeyStream(out, r.blob)

	// compute result
	result, err := scrypt.Key(out, []byte("gnunet-revocation-proof-of-work"), 2, 8, 2, 64)
	return math.NewIntFromBytes(result), nil
}

//----------------------------------------------------------------------
// Command types for Worker
//----------------------------------------------------------------------

// StartCmd starts the PoW calculation beginng at given nonce. If a
// revocation is initiated the first time, the nonce is 0. If the computation
// was interrupted (because the revocation service was shutting down), the
// computation can resume for the next unchecked nonce value.
// see: StartResponse
type StartCmd struct {
	ID   int      // Command identifier (to relate responses)
	task *RevData // RevData instance to be started
}

// PauseCmd temporarily pauses the calculation of a PoW.
// see: PauseResponse
type PauseCmd struct {
	ID     int // Command identifier (to relate responses)
	taskID int // identifier for PoW task
}

// ResumeCmd resumes a paused PoW calculation.
// see: ResumeResponse
type ResumeCmd struct {
	ID     int // Command identifier (to relate responses)
	taskID int // identifier for PoW task
}

// BreakCmd interrupts a running PoW calculation
type BreakCmd struct {
	ID     int // Command identifier (to relate responses)
	taskID int // identifier for PoW task
}

//----------------------------------------------------------------------
// Response types for Worker
//----------------------------------------------------------------------

// StartResponse is a reply to the StartCmd message
type StartResponse struct {
	ID     int   // Command identifier (to relate responses)
	taskID int   // identifier for PoW task
	err    error // error code (nil on success)
}

// PauseResponse is a reply to the PauseCmd message
type PauseResponse struct {
	ID  int   // Command identifier (to relate responses)
	err error // error code (nil on success)
}

// ResumeResponse is a reply to the ResumeCmd message
type ResumeResponse struct {
	ID  int   // Command identifier (to relate responses)
	err error // error code (nil on success)
}

// BreakResponse is a reply to the BreakCmd message
type BreakResponse struct {
	ID    int    // Command identifier (to relate responses)
	Nonce uint64 // last checked nonce value
}

//----------------------------------------------------------------------
// Worker instance
//----------------------------------------------------------------------

// Task represents a currently active PoW calculation
type Task struct {
	ID     int
	rev    *RevData
	active bool
}

// Worker is the revocation worker. It is responsible to manage ad schedule
// the proof-of-work tasks for revocations.
type Worker struct {
	tasks map[int]*Task
	wg    *sync.WaitGroup
}

func NewWorker() *Worker {
	return &Worker{
		tasks: make(map[int]*Task),
		wg:    new(sync.WaitGroup),
	}
}

func (w *Worker) Run(wg *sync.WaitGroup, cmdCh chan interface{}, responseCh chan interface{}) {
	defer wg.Done()
	for {
		select {
		case cmd := <-cmdCh:
			switch x := cmd.(type) {
			case *StartCmd:
				task := &Task{
					ID:     util.NextID(),
					rev:    x.task,
					active: true,
				}
				w.tasks[task.ID] = task
			}

		default:
			// compute a single round of currently active tasks
		}
	}
}
