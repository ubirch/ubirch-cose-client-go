package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

const expectedConfig = `{"secret32":"","registerAuth":"","env":"","postgresDSN":"","dbMaxOpenConns":"","dbMaxIdleConns":"","dbConnMaxLifetime":"","dbConnMaxIdleTime":"","TCP_addr":"","TLS":false,"TLSCertFile":"","TLSKeyFile":"","CSR_country":"","CSR_organization":"","debug":false,"logTextFormat":false,"certificateServer":"","certificateServerPubKey":"","reloadCertsEveryMinute":false,"KeyService":"","IdentityService":""}`

func TestConfig(t *testing.T) {
	configBytes := []byte(expectedConfig)

	config := &Config{}

	if err := json.Unmarshal(configBytes, config); err != nil {
		t.Errorf("Failed to unmarshal json config: %s", err)
	}

	jsonBytes, err := json.Marshal(config)
	if err != nil {
		t.Errorf("Failed to serialize config")
	}

	if !bytes.Equal(configBytes, jsonBytes) {
		t.Errorf("Failed to serialize config to json:\n"+
			"- expected: %s\n"+
			"-      got: %s", configBytes, jsonBytes)
	}
}

func TestConfig_Load_Full(t *testing.T) {
	conf := &Config{}
	err := conf.Load("", "example_config.json")
	if err != nil {
		t.Errorf("unable to load configuration: %s", err)
	}
}

func TestConfig_Load_Min(t *testing.T) {
	conf := &Config{}
	err := conf.Load("", "example_config_min.json")
	if err != nil {
		t.Errorf("unable to load configuration: %s", err)
	}
}