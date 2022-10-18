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
	"fmt"
	"gnunet/enums"
	"net"
)

//----------------------------------------------------------------------
// DNS-related resource records
//----------------------------------------------------------------------

// DNS CNAME record
type CNAME struct {
	Name string
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *CNAME) Coexist([]*enums.GNSSpec, string) (bool, enums.GNSFlag) {
	return true, 0
}

// ToMap adds the RR attributes to a stringed map
func (rr *CNAME) ToMap(params map[string]string) {
	params["dnscname_name"] = rr.Name
}

//----------------------------------------------------------------------

// DNS TXT record
type TXT struct {
	Text string
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *TXT) Coexist([]*enums.GNSSpec, string) (bool, enums.GNSFlag) {
	return true, 0
}

// ToMap adds the RR attributes to a stringed map
func (rr *TXT) ToMap(params map[string]string) {
	params["dnstxt_text"] = rr.Text
}

//----------------------------------------------------------------------

// DNS IPv4 address
type DNSA struct {
	Addr net.IP `size:"16"`
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *DNSA) Coexist([]*enums.GNSSpec, string) (bool, enums.GNSFlag) {
	return true, 0
}

// ToMap adds the RR attributes to a stringed map
func (rr *DNSA) ToMap(params map[string]string) {
	params["dnsa_addr"] = rr.Addr.String()
}

//----------------------------------------------------------------------

// DNS IPv6 address
type DNSAAAA struct {
	Addr net.IP `size:"16"`
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *DNSAAAA) Coexist([]*enums.GNSSpec, string) (bool, enums.GNSFlag) {
	return true, 0
}

// ToMap adds the RR attributes to a stringed map
func (rr *DNSAAAA) ToMap(params map[string]string) {
	params["dnsaaaa_addr"] = rr.Addr.String()
}

//----------------------------------------------------------------------

// MX is a DNS MX record
type MX struct {
	Prio   uint16 `order:"big"`
	Server string
}

// Coexist checks if a new resource record could coexist with given set
// of records under a label (can be called with a nil receiver)
func (rr *MX) Coexist([]*enums.GNSSpec, string) (bool, enums.GNSFlag) {
	return true, 0
}

// ToMap adds the RR attributes to a stringed map
func (rr *MX) ToMap(params map[string]string) {
	params["dnsmx_prio"] = fmt.Sprintf("%d", rr.Prio)
	params["dnsmx_host"] = rr.Server
}
