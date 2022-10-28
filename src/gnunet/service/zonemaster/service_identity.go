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
	"context"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service/store"
	"gnunet/transport"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
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
	zm      *ZoneMaster                      // reference to main service
	clients *util.Map[int, *IdentitySession] // client sessions
}

func NewIdentityService(zm *ZoneMaster) *IdentityService {
	srv := new(IdentityService)
	srv.zm = zm
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

func (ident *IdentityService) FollowUpdates(id int) *IdentitySession {
	if sess, ok := ident.clients.Get(id, 0); ok {
		sess.updates = true
		return sess
	}
	return nil
}

func (ident *IdentityService) Start(ctx context.Context, id int) (err error) {
	// flag client as update receiver
	sess := ident.FollowUpdates(id)
	if sess == nil {
		err = fmt.Errorf("no session available for client %d", id)
		return
	}
	// initial update is to send all existing identites
	var list []*store.Zone
	if list, err = ident.zm.zdb.GetZones(""); err != nil {
		return
	}
	for _, ident := range list {
		resp := message.NewIdentityUpdateMsg(ident.Name, ident.Key)
		logger.Printf(logger.DBG, "[identity:%d] Sending %v", id, resp)
		if err = sess.back.Send(ctx, resp); err != nil {
			logger.Printf(logger.ERROR, "[identity:%d] Can't send response (%v): %v\n", id, resp, err)
			return
		}
	}
	// terminate with EOL
	resp := message.NewIdentityUpdateMsg("", nil)
	if err = sess.back.Send(ctx, resp); err != nil {
		logger.Printf(logger.ERROR, "[identity:%d] Can't send response (%v): %v\n", id, resp, err)
		return
	}
	return
}

func (ident *IdentityService) Create(ctx context.Context, cid int, zk *crypto.ZonePrivate, name string) (err error) {
	// get client session
	sess, ok := ident.clients.Get(cid, 0)
	if !ok {
		err = fmt.Errorf("no session available for client %d", cid)
		return
	}
	// add identity
	id := store.NewZone(name, zk)
	err = ident.zm.zdb.SetZone(id)
	rc := enums.RC_OK
	msg := ""
	if err != nil {
		rc = enums.RC_NO
		msg = err.Error()
	}
	resp := message.NewIdentityResultCodeMsg(rc, msg)
	if err = sess.back.Send(ctx, resp); err != nil {
		logger.Printf(logger.ERROR, "[identity:%d] Can't send response (%v): %v\n", cid, resp, err)
		return
	}
	return
}
