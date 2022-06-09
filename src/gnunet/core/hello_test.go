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

package core

import (
	"fmt"
	"gnunet/config"
	"gnunet/service/dht/blocks"
	"gnunet/util"
	"testing"
	"time"
)

var (
	peerCfg = &config.NodeConfig{
		Name:        "p1",
		PrivateSeed: "iYK1wSi5XtCP774eNFk1LYXqKlOPEpwKBw+2/bMkE24=",
		Endpoints: []*config.EndpointConfig{
			{
				ID:      "p1",
				Network: "ip+udp",
				Address: "172.17.0.1",
				Port:    2086,
				TTL:     86400,
			},
		},
	}

	helloURLFail = "gnunet://hello" +
		"/A02QJQ93GPBFVPJ4ZEY3JTS4HS00NG5PZBM7VXR0P9CRP18MZTN0" +
		"/SBNGD3ZDMZ953GZ4JXMKEKHG1EFADE6SVGQ7ZJXGM95H387T4BYZT87TC8D6G22ZRRNDZT83K6KZQS6TR59SMNZ9MZJK6533XTDJW0G" +
		"/1654780105" +
		"?ip+udp=172.17.0.1%3A2086"

	helloURLOK = "gnunet://hello" +
		"/A02QJQ93GPBFVPJ4ZEY3JTS4HS00NG5PZBM7VXR0P9CRP18MZTN0" +
		"/TJR1PYY8M7EJAT8Y4ABDAFM318ATEJ87EJ6SXHCDJF03F1AAPNDXA51MDJ6D5PZ0YB17NPAD0GR60V34100BQT2YGWP46CER4HCT21G" +
		"/1654782536" +
		"?ip+udp=172.17.0.1%3A2086"
)

func TestHelloURLDirect(t *testing.T) {
	if _, err := blocks.ParseHelloURL(helloURLFail, false); err == nil {
		t.Fatal("no error on bad HELLO URL")
	}
	if _, err := blocks.ParseHelloURL(helloURLOK, false); err != nil {
		t.Fatal(err)
	}
}

func TestHelloURL(t *testing.T) {

	// prepare peer and HELLO data
	peer, err := NewLocalPeer(peerCfg)
	if err != nil {
		t.Fatal(err)
	}
	as := fmt.Sprintf("%s://%s:%d",
		peerCfg.Endpoints[0].Network,
		peerCfg.Endpoints[0].Address,
		peerCfg.Endpoints[0].Port,
	)
	listen, err := util.ParseAddress(as)
	if err != nil {
		t.Fatal(err)
	}
	aList := []*util.Address{listen}
	hd, err := peer.HelloData(time.Hour, aList)
	if err != nil {
		t.Fatal(err)
	}

	// convert to and from HELLO URL
	url1 := hd.URL()
	t.Log(">>> " + url1)
	hd2, err := blocks.ParseHelloURL(url1, true)
	if err != nil {
		t.Fatal(err)
	}
	url2 := hd2.URL()
	t.Log("<<< " + url2)
	if url1 != url2 {
		t.Fatal("urls don't match")
	}
}
