// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2022 Bernd Fix  >Y<
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

package core

import (
	"context"
	"gnunet/config"
	"gnunet/message"
	"testing"
	"time"
)

const (
	ADDR = "udp:127.0.0.1:6765"
)

func TestCoreSimple(t *testing.T) {

	// setup execution context
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		time.Sleep(time.Second)
	}()

	// create local peer
	localCfg := &config.NodeConfig{
		PrivateSeed: "YGoe6XFH3XdvFRl+agx9gIzPTvxA229WFdkazEMdcOs=",
		Endpoints:   []string{ADDR},
	}
	local, err := NewLocalPeer(localCfg)
	if err != nil {
		t.Fatal(err)
	}

	// create core service
	core, err := NewCore(ctx, local)
	if err != nil {
		t.Fatal(err)
	}

	// register as listener
	filter := NewEventFilter()
	incoming := make(chan *Event)
	core.Register("test", NewListener(incoming, filter))

	// run event handler
	go func() {
		for {
			select {
			case ev := <-incoming:
				t.Logf("<<< Event %v", ev)
			case <-ctx.Done():
				t.Log("Shutting down server")
				return
			}
		}
	}()

	// send HELLO message to transport
	hello, err := local.HelloData(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	msg := message.NewHelloMsg(local.GetID())
	for _, a := range hello.Addresses() {
		ha := message.NewHelloAddress(a)
		msg.AddAddress(ha)
	}
	core.Send(local.GetID(), msg)
}
