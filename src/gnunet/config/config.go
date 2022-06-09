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

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"regexp"
	"strings"

	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// Configuration for local node
//----------------------------------------------------------------------

// EndpointConfig holds parameters for local network listeners.
type EndpointConfig struct {
	ID      string `json:"id"`      // endpoint identifier
	Network string `json:"network"` // network protocol to use on endpoint
	Address string `json:"address"` // address to listen on
	Port    int    `json:"port"`    // port for listening to network
	TTL     int    `json:"ttl"`     // time-to-live for address (in seconds)
}

// Addr returns an address string for endpoint configuration; it does NOT
// handle special cases like UPNP and such.
func (c *EndpointConfig) Addr() string {
	return fmt.Sprintf("%s://%s:%d", c.Network, c.Address, c.Port)
}

// NodeConfig holds parameters for the local node instance
type NodeConfig struct {
	Name        string            `json:"name"`        // (short) name for local node
	PrivateSeed string            `json:"privateSeed"` // Node private key seed (base64)
	Endpoints   []*EndpointConfig `json:"endpoints"`   // list of endpoints available
}

//----------------------------------------------------------------------
// Bootstrap configuration
//----------------------------------------------------------------------

// BootstrapConfig holds parameters for the initial connection to the network.
type BootstrapConfig struct {
	Nodes []string `json:"nodes"` // bootstrap nodes
}

//----------------------------------------------------------------------
// RPC configuration
//----------------------------------------------------------------------

// RPCConfig contains parameters for the JSON-RPC service
type RPCConfig struct {
	Endpoint string `json:"endpoint"` // endpoint for JSON-RPC service
}

//----------------------------------------------------------------------
// Generic service endpoint configuration (socket)
//----------------------------------------------------------------------

type ServiceConfig struct {
	Socket string            `json:"socket"` // socket file name
	Params map[string]string `json:"params"` // socket parameters
}

//----------------------------------------------------------------------
// GNS configuration
//----------------------------------------------------------------------

// GNSConfig contains parameters for the GNU Name System service
type GNSConfig struct {
	Service      *ServiceConfig `json:"service"`      // socket for GNS service
	DHTReplLevel int            `json:"dhtReplLevel"` // DHT replication level
	MaxDepth     int            `json:"maxDepth"`     // maximum recursion depth in resolution
}

//----------------------------------------------------------------------
// DHT configuration
//----------------------------------------------------------------------

// DHTConfig contains parameters for the distributed hash table (DHT)
type DHTConfig struct {
	Service *ServiceConfig `json:"service"` // socket for DHT service
	Storage string         `json:"storage"` // filesystem storage location
	Cache   string         `json:"cache"`   // key/value cache
}

//----------------------------------------------------------------------
// Namecache configuration
//----------------------------------------------------------------------

// NamecacheConfig contains parameters for the local name cache
type NamecacheConfig struct {
	Service *ServiceConfig `json:"service"` // socket for Namecache service
	Storage string         `json:"storage"` // key/value cache
}

//----------------------------------------------------------------------
// Revocation configuration
//----------------------------------------------------------------------

// RevocationConfig contains parameters for the key revocation service
type RevocationConfig struct {
	Service *ServiceConfig `json:"service"` // socket for Revocation service
	Storage string         `json:"storage"` // persistance mechanism for revocation data
}

//----------------------------------------------------------------------
// Combined configuration
//----------------------------------------------------------------------

// Environment settings
type Environment map[string]string

// Config is the aggregated configuration for GNUnet.
type Config struct {
	Local      *NodeConfig       `json:"local"`
	Bootstrap  *BootstrapConfig  `json:"bootstrap"`
	Env        Environment       `json:"environ"`
	RPC        *RPCConfig        `json:"rpc"`
	DHT        *DHTConfig        `json:"dht"`
	GNS        *GNSConfig        `json:"gns"`
	Namecache  *NamecacheConfig  `json:"namecache"`
	Revocation *RevocationConfig `json:"revocation"`
}

var (
	// Cfg is the global configuration
	Cfg *Config
)

// ParseConfig converts a JSON-encoded configuration file and maps it to
// the Config data structure.
func ParseConfig(fileName string) (err error) {
	// parse configuration file
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return
	}
	return ParseConfigBytes(file, true)
}

// ParseConfigBytes reads a configuration from binary data. The data is
// a JSON-encoded content. If 'subst' is true, the configuration strings
// are subsituted
func ParseConfigBytes(data []byte, subst bool) (err error) {
	// unmarshal to Config data structure
	Cfg = new(Config)
	if err = json.Unmarshal(data, Cfg); err == nil {
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
