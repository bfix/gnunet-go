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

package config

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/bfix/gospel/logger"
)

func TestConfigRead(t *testing.T) {
	logger.SetLogLevel(logger.WARN)

	// read configuration file
	data, err := ioutil.ReadFile("./gnunet-config.json")
	if err != nil {
		t.Fatal(err)
	}
	// parse configuration
	if err := ParseConfigBytes(data, false); err != nil {
		t.Fatal(err)
	}
	// write configuration
	if _, err = json.Marshal(Cfg); err != nil {
		t.Fatal(err)
	}
}
