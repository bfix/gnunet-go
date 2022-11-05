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

package zonemaster

import (
	"gnunet/enums"
)

// ZoneMasterUtility can perform utility functions on behalf of plugins
var ZoneMasterUtility = func(fcn string, args ...any) any {
	switch fcn {
	case "gns_type_name":
		return enums.GNSType(args[0].(uint32)).String()
	case "gns_flags":
		return enums.GNSFlag(args[0].(uint32)).List()
	}
	return nil
}

// ZoneMasterPlugin handles resource record type specific functionality
type Plugin interface {
	// SetUtility passes a utility function to plugins
	// (Callback-like function)
	SetUtility(any)

	// Name of the plugin
	Name() string

	// CanHandle returns a list of resource record types
	CanHandle() []uint32

	// Compute a set of record specs allowed under a label with existing records
	Compatible(label string, rrSpecs [][2]uint32) [][2]uint32

	// Value returns a human-readable description of RR data
	Value(t uint32, rr []byte) (string, error)

	// Template returns the new / edit template for custom types
	Template() string

	// TemplateNames returns the names for the "new" and "edit" dialogs
	TemplateNames() (string, string)

	// Prefix returns the prefix for record attributes in map
	Prefix(t uint32) string

	// ToMap converts resource record data into GUI template variables
	ToMap(t uint32, rr []byte) (map[string]string, error)

	// FromMap converts a GUI template variables into resource record data
	FromMap(t uint32, vars map[string]string) ([]byte, error)
}
