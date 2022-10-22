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

package store

import (
	"crypto/rand"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"
	"os"
	"testing"
	"time"
)

func TestZoneMaster(t *testing.T) {

	//------------------------------------------------------------------
	// create database
	_ = os.Remove("/tmp/zonemaster.db")
	zdb, err := OpenZoneDB("/tmp/zonemaster.db")
	if err != nil {
		t.Fatal(err)
	}

	//------------------------------------------------------------------
	// create zone and add zone to database
	seed := make([]byte, 32)
	if _, err = rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	zp, err := crypto.NewZonePrivate(enums.GNS_TYPE_PKEY, seed)
	if err != nil {
		t.Fatal(err)
	}
	zone := NewZone("foo", zp)
	if err = zdb.SetZone(zone); err != nil {
		t.Fatal(err)
	}

	//------------------------------------------------------------------
	// create label and add to zone and database
	label := NewLabel("bar")
	label.Zone = zone.ID
	if err = zdb.SetLabel(label); err != nil {
		t.Fatal(err)
	}

	//------------------------------------------------------------------
	// add record to label and database
	rec := NewRecord(util.AbsoluteTimeNever().Add(time.Hour), enums.GNS_TYPE_DNS_TXT, 0, []byte("test entry"))
	rec.Label = label.ID
	if err = zdb.SetRecord(rec); err != nil {
		t.Fatal(err)
	}

	//------------------------------------------------------------------
	// search record in database
	recs, err := zdb.GetRecords("rtype=%d", enums.GNS_TYPE_DNS_TXT)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("record: got %d records, expected 1", len(recs))
	}

	//------------------------------------------------------------------
	// rename zone
	zone.Name = "MyZone"
	zone.Modified = util.AbsoluteTimeNow()
	if err = zdb.SetZone(zone); err != nil {
		t.Fatal(err)
	}

	//------------------------------------------------------------------
	// search zone in database
	zones, err := zdb.GetZones("name like 'My%%'")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 {
		t.Fatalf("zone: got %d records, expected 1", len(zones))
	}

	//------------------------------------------------------------------
	// close database
	if err = zdb.Close(); err != nil {
		t.Fatal(err)
	}
}
