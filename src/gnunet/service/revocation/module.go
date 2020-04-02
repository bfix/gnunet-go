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
	"gnunet/service"

	"github.com/bfix/gospel/crypto/ed25519"
)

//======================================================================
// "GNUnet Revocation" implementation
//======================================================================

// RevocationModule handles the revocation-related calls to other modules.
type RevocationModule struct {
	// Use function references for calls to methods in other modules:
}

// Query
func (s *RevocationModule) RevocationQuery(ctx *service.SessionContext, pkey *ed25519.PublicKey) (valid bool, err error) {
	return false, nil
}

// Revoke
func (s *RevocationModule) RevocationRevoke(ctx *service.SessionContext, nonce uint64, pkey *ed25519.PublicKey) (valid bool, err error) {
	return false, nil
}
