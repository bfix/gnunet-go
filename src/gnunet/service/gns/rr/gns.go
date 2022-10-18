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
	"gnunet/crypto"
	"gnunet/enums"
)

//----------------------------------------------------------------------
// GNS resource records
//----------------------------------------------------------------------

// PKEY (Ed25519+EcDSA) zone key
type PKEY struct {
	*crypto.ZoneKey
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *PKEY) Coexist(list []*enums.GNSSpec, label string) (ok bool, forced enums.GNSFlag) {
	// can't add PKEY to apex label
	if label == "@" {
		return
	}
	// make sure all existing records are PKEYs too
	for _, e := range list {
		if e.Type != enums.GNS_TYPE_PKEY {
			// check failed on non-PKEY
			return
		}
		// check for active PKEY
		if e.Flags&enums.GNS_FLAG_SHADOW == 0 {
			// only additional shaow records allowed
			forced = enums.GNS_FLAG_SHADOW
		}
	}
	ok = true
	return
}

// ToMap adds the RR attributes to a stringed map
func (rr *PKEY) ToMap(params map[string]string) {
	params["pkey_data"] = rr.ID()
}

//----------------------------------------------------------------------

// EDKEY (EdDSA) zone key
type EDKEY struct {
	*crypto.ZoneKey
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *EDKEY) Coexist(list []*enums.GNSSpec, label string) (ok bool, forced enums.GNSFlag) {
	// can't add EDKEY to apex label
	if label == "@" {
		return
	}
	// make sure all existing records are EDKEYs too
	for _, e := range list {
		if e.Type != enums.GNS_TYPE_EDKEY {
			// check failed on non-EDKEY
			return
		}
		// check for active PKEY
		if e.Flags&enums.GNS_FLAG_SHADOW == 0 {
			// only additional shaow records allowed
			forced = enums.GNS_FLAG_SHADOW
		}
	}
	ok = true
	return
}

// ToMap adds the RR attributes to a stringed map
func (rr *EDKEY) ToMap(params map[string]string) {
	params["edkey_data"] = rr.ID()
}

//----------------------------------------------------------------------

// REDIRECT to name
type REDIRECT struct {
	Name string
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *REDIRECT) Coexist(list []*enums.GNSSpec, label string) (ok bool, forced enums.GNSFlag) {
	// no REDIRECT in apex zone
	if label == "@" {
		return
	}
	// make sure all existing records are supplemental EDKEYs too
	for _, e := range list {
		if e.Type != enums.GNS_TYPE_REDIRECT && e.Flags&enums.GNS_FLAG_SUPPL == 0 {
			// check failed on non-supplemental non-REDIRECT record
			return
		}
		// check for active REDIRECT
		if e.Flags&enums.GNS_FLAG_SHADOW == 0 {
			// only additional shaow records allowed
			forced = enums.GNS_FLAG_SHADOW
		}
	}
	ok = true
	return
}

// ToMap adds the RR attributes to a stringed map
func (rr *REDIRECT) ToMap(params map[string]string) {
	params["redirect_name"] = rr.Name
}

//----------------------------------------------------------------------

// GNS NICK record
type NICK struct {
	Name string
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *NICK) Coexist(list []*enums.GNSSpec, label string) (ok bool, forced enums.GNSFlag) {
	// can only be added to the apex label
	if label != "@" {
		return
	}
	// only one un-shadowed NICK allowed
	for _, e := range list {
		if e.Type == enums.GNS_TYPE_NICK && e.Flags&enums.GNS_FLAG_SHADOW == 0 {
			// only additional shadow records allowed
			forced = enums.GNS_FLAG_SHADOW
		}
	}
	ok = true
	return
}

// ToMap adds the RR attributes to a stringed map
func (rr *NICK) ToMap(params map[string]string) {
	params["nick_name"] = rr.Name
}

//----------------------------------------------------------------------

// LEHO record
type LEHO struct {
	Name string
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *LEHO) Coexist([]*enums.GNSSpec, string) (bool, enums.GNSFlag) {
	return true, 0
}

// ToMap adds the RR attributes to a stringed map
func (rr *LEHO) ToMap(params map[string]string) {
	params["leho_name"] = rr.Name
}

//----------------------------------------------------------------------

// GNS2DNS delegation
type GNS2DNS struct {
	Name   string
	Server string
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *GNS2DNS) Coexist([]*enums.GNSSpec, string) (bool, enums.GNSFlag) {
	return true, 0
}

// ToMap adds the RR attributes to a stringed map
func (rr *GNS2DNS) ToMap(params map[string]string) {
	params["gns2dns_name"] = rr.Name
	params["gns2dns_server"] = rr.Server
}
