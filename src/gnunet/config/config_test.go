package config

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestConfigRead(t *testing.T) {
	if err := ParseConfig("./gnunet-config.json"); err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		data, err := json.Marshal(Cfg)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("cfg=" + string(data))
	}
}
