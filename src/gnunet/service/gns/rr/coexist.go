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

package rr

import (
	"errors"
	"gnunet/enums"
	"gnunet/util"

	"github.com/bfix/gospel/data"
)

// RR interface for resource records
type RR interface {
	// Coexist checks if a new resource record could coexist with given set
	// of records under a label (can be called with a nil receiver)
	Coexist(list []*enums.GNSSpec, label string) (bool, enums.GNSFlag)

	// ToMap adds the RR attributes to a stringed map
	ToMap(map[string]string, string)
}

// CanCoexist checks if a (new) resource record of type 't' can coexist
// with a given set of resource records. If ok is true, it can enforce
// flags for the new record.
func CanCoexist(t enums.GNSType, list []*enums.GNSSpec, label string) (ok bool, forced enums.GNSFlag) {
	rr := NilRR(t)
	if rr == nil {
		return true, 0
	}
	// check if new record against list
	if ok, forced = rr.Coexist(list, label); !ok {
		return
	}
	// now check if each existing record can coexists with a modified list
	// swpping new record and tested record.
	testList := util.Clone(list)
	eNew := &enums.GNSSpec{
		Type:  t,
		Flags: forced,
	}
	for i, e := range testList {
		// skip unknown types
		if rr = NilRR(e.Type); rr == nil {
			return true, 0
		}
		// check replacement
		testList[i] = eNew
		ok, forced = rr.Coexist(testList, label)
		if !ok {
			return
		}
		eNew.Flags |= forced
		testList[i] = e
	}
	// all checks passed
	forced = eNew.Flags
	return
}

// ParseRR returns a RR instance from data for given type
func ParseRR(t enums.GNSType, buf []byte) (rr RR, err error) {
	// get record instance
	if rr = NewRR(t); rr == nil {
		err = errors.New("parse RR failed")
		return
	}
	// reconstruct record
	err = data.Unmarshal(rr, buf)
	return
}

// NewRR returns a new RR instance of given type
func NewRR(t enums.GNSType) RR {
	switch t {
	case enums.GNS_TYPE_PKEY:
		return new(PKEY)
	case enums.GNS_TYPE_EDKEY:
		return new(EDKEY)
	case enums.GNS_TYPE_REDIRECT:
		return (*REDIRECT)(nil)
	case enums.GNS_TYPE_NICK:
		return new(NICK)
	case enums.GNS_TYPE_LEHO:
		return new(LEHO)
	case enums.GNS_TYPE_GNS2DNS:
		return new(GNS2DNS)
	case enums.GNS_TYPE_BOX:
		return new(BOX)
	case enums.GNS_TYPE_DNS_CNAME:
		return new(CNAME)
	case enums.GNS_TYPE_DNS_A:
		return new(DNSA)
	case enums.GNS_TYPE_DNS_AAAA:
		return new(DNSAAAA)
	case enums.GNS_TYPE_DNS_MX:
		return new(MX)
	case enums.GNS_TYPE_DNS_TXT:
		return new(TXT)
	}
	return nil
}

// NilRR returns a typed nil reference to a RR that can be used to
// call type methods that allow a nil receiver.
func NilRR(t enums.GNSType) RR {
	switch t {
	case enums.GNS_TYPE_PKEY:
		return (*PKEY)(nil)
	case enums.GNS_TYPE_EDKEY:
		return (*EDKEY)(nil)
	case enums.GNS_TYPE_REDIRECT:
		return (*REDIRECT)(nil)
	case enums.GNS_TYPE_NICK:
		return (*NICK)(nil)
	case enums.GNS_TYPE_LEHO:
		return (*LEHO)(nil)
	case enums.GNS_TYPE_GNS2DNS:
		return (*GNS2DNS)(nil)
	case enums.GNS_TYPE_BOX:
		return (*BOX)(nil)
	case enums.GNS_TYPE_DNS_CNAME:
		return (*CNAME)(nil)
	case enums.GNS_TYPE_DNS_A:
		return (*DNSA)(nil)
	case enums.GNS_TYPE_DNS_AAAA:
		return (*DNSAAAA)(nil)
	case enums.GNS_TYPE_DNS_MX:
		return (*MX)(nil)
	case enums.GNS_TYPE_DNS_TXT:
		return (*TXT)(nil)
	}
	// return untyped nil
	return nil
}
