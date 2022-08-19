// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2022 Bernd Fix  >Y<
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

package path

import (
	"encoding/hex"
	"gnunet/util"
	"testing"
)

func TestElementDebug(t *testing.T) {
	var (
		signedData = "" +
			"008C" +
			"0006" +
			"0005e6983d33f911" +
			"f3236acc2be7812a988617c647fc27fcfbd0dacc3d960aa29a5f9bf0b9b9131f" +
			"cdd31cfa45de2cbd9510665e7f2b1ccafefd445511c62729c0798dd1b0675f19" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"23b096021b25d822c217a756b877cf72c7fdabd4eff79c4dbb7418dd2b232386"

		signature = "" +
			"ef94ddfd90b56f30b265a88384551907fadef176b4ba6b023df429506b34cde0" +
			"39f38661d451e6e5bd1c4d5d078d27f0e8954bd964ea55f03afa42aa9964cc0c"
		signer = "" +
			"28f06fe5178742c3b8f080431e48cf5bf3898ba8b8fd57a975772d14003a8c75"
		predecessor = "" +
			"0000000000000000000000000000000000000000000000000000000000000000"
		successor = "" +
			"23b096021b25d822c217a756b877cf72c7fdabd4eff79c4dbb7418dd2b232386"
	)
	convert := func(s string) []byte {
		buf, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return buf
	}
	sd := convert(signedData)
	sig := util.NewPeerSignature(convert(signature))
	pred := util.NewPeerID(convert(predecessor))
	curr := util.NewPeerID(convert(signer))
	succ := util.NewPeerID(convert(successor))

	ok, err := curr.Verify(sd, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Log("Verify NOT OK:")
		t.Logf("Pred: %s", pred.Short())
		t.Logf("Sign: %s", curr.Short())
		t.Logf("Succ: %s", succ.Short())
	}
}
