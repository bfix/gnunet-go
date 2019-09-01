package config

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestConfigRead(t *testing.T) {
	cfg, err := ParseConfig("./gnunet-config.json")
	if err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("cfg=" + string(data))
	}
}
