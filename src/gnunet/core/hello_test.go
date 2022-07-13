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

	helloURL = []string{
		"gnunet://hello" +
			"/RBVQWST48N9YDVHYM7KYR1YDBZN7X4KG1SJJZHGHGX5HFHX5P010" +
			"/Y4YEXZBBKS1HFGGHZW5QWQTX20QJ5BBEQZB8PNA85VCASRR60P741X28E8HS6P20HQED43RAQFADJTVREFQ37W1YQFN29TCC2AT4R2R" +
			"/1654964519" +
			"?ip+udp=127.0.0.1%3A10000" +
			"&ip+udp=192.168.178.50%3A10000" +
			"&ip+udp=%5B%3A%3A1%5D%3A10000" +
			"&ip+udp=%5B2001%3A1620%3Afe9%3A0%3A7285%3Ac2ff%3Afe62%3Ab4c9%5D%3A10000" +
			"&ip+udp=%5Bfe80%3A%3A7285%3Ac2ff%3Afe62%3Ab4c9%5D%3A10000",
		"gnunet://hello" +
			"/6SR91X40JHTTSKTEY04KC920MDJBVDDNJ9Y2KPVY1RJK40KC1SVG" +
			"/7H3BX1XDYXKXDR20X1GPCYY1CT68GGH1CC9FSDBW4MZ4H5GFB3K7PMJZTEWK3NVVJ0FXBBG6QFBWFM233F5YTQZGZ8JV5MEPNBWP800" +
			"/1654953178" +
			"?ip+udp=127.0.0.1%3A10000" +
			"&ip+udp=172.17.0.4%3A10000" +
			"&ip+udp=%5B%3A%3Affff%3A172.17.0.4%5D%3A10000",
	}
)

func TestHelloURLDirect(t *testing.T) {
	for _, hu := range helloURL {
		if _, err := blocks.ParseHelloURL(hu, false); err != nil {
			t.Fatal(err)
		}
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
	hd2, err := blocks.ParseHelloURL(url1, true)
	if err != nil {
		t.Fatal(err)
	}
	url2 := hd2.URL()
	if url1 != url2 {
		t.Log(">>> " + url1)
		t.Log("<<< " + url2)
		t.Fatal("urls don't match")
	}
}
