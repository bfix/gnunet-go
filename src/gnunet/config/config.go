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
	"reflect"
	"regexp"
	"strings"

	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
)

///////////////////////////////////////////////////////////////////////
// GNS configuration

// GNSConfig
type GNSConfig struct {
	Endpoint     string            `json:"endpoint"`     // end-point of GNS service
	DHTReplLevel int               `json:"dhtReplLevel"` // DHT replication level
	RootZones    map[string]string `json:"rootZones"`    // pre-configured root zones
}

// GetRootZoneKey returns the zone key (PKEY) for a pre-configured root with given name.
func (gns *GNSConfig) GetRootZoneKey(name string) *ed25519.PublicKey {
	// lookup key in the dictionary
	if dStr, ok := gns.RootZones[name]; ok {
		if data, err := util.DecodeStringToBinary(dStr, 32); err == nil {
			return ed25519.NewPublicKeyFromBytes(data)
		}
	}
	// no pkey found.
	return nil
}

///////////////////////////////////////////////////////////////////////
// DHT configuration

// DHTConfig
type DHTConfig struct {
	Endpoint string `json:"endpoint"` // end-point of DHT service
}

///////////////////////////////////////////////////////////////////////
// Namecache configuration

// NamecacheConfig
type NamecacheConfig struct {
	Endpoint string `json:"endpoint"` // end-point of Namecache service
}

///////////////////////////////////////////////////////////////////////

// Environment settings
type Environ map[string]string

// Config is the aggregated configuration for GNUnet.
type Config struct {
	Env       Environ          `json:"environ"`
	DHT       *DHTConfig       `json:"dht"`
	GNS       *GNSConfig       `json:"gns"`
	Namecache *NamecacheConfig `json:"namecache"`
}

var (
	// Cfg is the global configuration
	Cfg *Config
)

// Parse a JSON-encoded configuration file map it to the Config data structure.
func ParseConfig(fileName string) (err error) {
	// parse configuration file
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return
	}
	// unmarshal to Config data structure
	Cfg = new(Config)
	if err = json.Unmarshal(file, Cfg); err == nil {
		// process all string-based config settings and apply
		// string substitutions.
		applySubstitutions(Cfg, Cfg.Env)
	}
	return
}

var (
	rx = regexp.MustCompile("\\$\\{([^\\}]*)\\}")
)

// substString is a helper function to substitute environment variables
// with actual values.
func substString(s string, env map[string]string) string {
	matches := rx.FindAllStringSubmatch(s, -1)
	for _, m := range matches {
		if len(m[1]) != 0 {
			subst, ok := env[m[1]]
			if !ok {
				continue
			}
			s = strings.Replace(s, "${"+m[1]+"}", subst, -1)
		}
	}
	return s
}

// applySubstitutions traverses the configuration data structure
// and applies string substitutions to all string values.
func applySubstitutions(x interface{}, env map[string]string) {

	var process func(v reflect.Value)
	process = func(v reflect.Value) {
		for i := 0; i < v.NumField(); i++ {
			fld := v.Field(i)
			if fld.CanSet() {
				switch fld.Kind() {
				case reflect.String:
					// check for substitution
					s := fld.Interface().(string)
					for {
						s1 := substString(s, env)
						if s1 == s {
							break
						}
						logger.Printf(logger.DBG, "[config] %s --> %s\n", s, s1)
						fld.SetString(s1)
						s = s1
					}

				case reflect.Struct:
					// handle nested struct
					process(fld)

				case reflect.Ptr:
					// handle pointer
					e := fld.Elem()
					if e.IsValid() {
						process(fld.Elem())
					} else {
						logger.Printf(logger.ERROR, "[config] 'nil' pointer encountered")
					}
				}
			}
		}
	}
	// start processing at the top-level structure
	v := reflect.ValueOf(x)
	switch v.Kind() {
	case reflect.Ptr:
		// indirect top-level
		e := v.Elem()
		if e.IsValid() {
			process(e)
		} else {
			logger.Printf(logger.ERROR, "[config] 'nil' pointer encountered")
		}
	case reflect.Struct:
		// direct top-level
		process(v)
	}
}
