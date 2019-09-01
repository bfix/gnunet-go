package config

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"regexp"
	"strings"

	"github.com/bfix/gospel/logger"
	"gnunet/service/dht"
	"gnunet/service/gns"
)

// Environment settings
type Environ map[string]string

// Config is the aggregated configuration for GNUnet.
type Config struct {
	Env Environ     `json:"environ"`
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
	if err = json.Unmarshal(file, config); err == nil {
		// process all string-based config settings and apply
		// string substitutions.
		applySubstitutions(config, config.Env)
	}
	return
}

var (
	rx = regexp.MustCompile("\\$\\{([^\\}]*)\\}")
)

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

// applySubstitutions
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

	v := reflect.ValueOf(x)
	switch v.Kind() {
	case reflect.Ptr:
		e := v.Elem()
		if e.IsValid() {
			process(e)
		} else {
			logger.Printf(logger.ERROR, "[config] 'nil' pointer encountered")
		}
	case reflect.Struct:
		process(v)
	}
}
