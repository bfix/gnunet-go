package config

import (
	"encoding/json"
	"io/ioutil"

	"gnunet/service/dht"
	"gnunet/service/gns"
)

// Config is the aggregated configuration for GNUnet.
type Config struct {
	DHT *dht.Config `json:"dht"`
	GNS *gns.Config `json:"gns"`
}

// Parse a JSON-encoded configuration file map it to the Config data structure.
func ParseConfig(fileName string) (config *Config, err error) {
	// parse configuration file
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	// unmarshal to Config data structure
	config = new(Config)
	err = json.Unmarshal(file, config)
	return
}
