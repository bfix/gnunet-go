package config

import (
	"encoding/json"
	"testing"

	"github.com/bfix/gospel/logger"
)

func TestConfigRead(t *testing.T) {
	logger.SetLogLevel(logger.WARN)
	if err := ParseConfig("./gnunet-config.json"); err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		data, err := json.Marshal(Cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("cfg=" + string(data))
	}
}
