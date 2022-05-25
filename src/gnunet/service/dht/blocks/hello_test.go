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

package blocks

import "testing"

const (
	helloURL = "gnunet://hello" +
		"/7KTBJ90340HF1Q2GB0A57E2XJER4FDHX8HP5GHEB9125VPWPD27G" +

		"/BNMDFN6HJCPWSPNBSEC06MC1K8QN1Z2DHRQSRXDTFR7FTBD4JHN" +
		"BJ2RJAAEZ31FWG1Q3PMN3PXGZQ3Q7NTNEKQZFA7TE2Y46FM8E20R" +
		"/1653499308" +
		"?r5n%2Bip%2Budp%3A1.2.3.4%3A6789" +
		"&gnunet%2Btcp%3A12.3.4.5"
)

func TestHelloURL(t *testing.T) {

	hd, err := ParseHelloURL(helloURL)
	if err != nil {
		t.Fatal(err)
	}
	u := hd.URL()
	if u != helloURL {
		t.Fatal("urls don't match")
	}
}
