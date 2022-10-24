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
	"gnunet/transport"
	"gnunet/util"
)

//----------------------------------------------------------------------
// "GNUnet Identity" service implementation:
//----------------------------------------------------------------------

type IdentitySession struct {
	id      int
	updates bool
	back    transport.Responder
}

type Identity struct{}

type IdentityService struct {
	defaults *util.Map[string, int64]
	clients  *util.Map[int, *IdentitySession]
}

func NewIdentityService() *IdentityService {
	srv := new(IdentityService)
	srv.defaults = util.NewMap[string, int64]()
	srv.clients = util.NewMap[int, *IdentitySession]()
	return srv
}

func (ident *IdentityService) NewSession(id int, back transport.Responder) {
	sess := &IdentitySession{
		id:      id,
		updates: false,
		back:    back,
	}
	ident.clients.Put(id, sess, 0)
}

func (ident *IdentityService) CloseSession(id int) {
	ident.clients.Delete(id, 0)
}

func (ident *IdentityService) FollowUpdates(id int) {
	if sess, ok := ident.clients.Get(id, 0); ok {
		sess.updates = true
	}
}