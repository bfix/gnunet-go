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

package util

import (
	"testing"
)

func TestAddrList(t *testing.T) {
	// list of addresses to check
	addrS := []string{
		"ip+udp://127.0.0.1:10000",
		"ip+udp://172.17.0.4:10000",
		"ip+udp://[::ffff:172.17.0.4]:10000",
	}
	// convert to util.Address
	addrA := make([]*Address, len(addrS))
	var err error
	for i, as := range addrS {
		if addrA[i], err = ParseAddress(as); err != nil {
			t.Fatal(err)
		}
	}
	// allocate AddrList
	addrL := NewPeerAddrList()
	for _, addr := range addrA {
		rc := addrL.Add("2BHV4BN8736W5W3CJNXY2S9WABWTGH35QMFG4BPCWBH7DNBCFC60", addr)
		t.Logf("added %s (%d)", addr.URI(), rc)
	}

	// check list
	t.Log("checking list...")
	list := addrL.Get("2BHV4BN8736W5W3CJNXY2S9WABWTGH35QMFG4BPCWBH7DNBCFC60", "ip+udp")
	t.Logf("got: %v", list)
	if len(list) != len(addrS) {
		t.Fatal("list size not matching")
	}
}
