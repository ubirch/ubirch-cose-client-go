package config

import (
	"bytes"
	"encoding/json"
	"testing"

	log "github.com/sirupsen/logrus"
)

const expectedConfig = `{"registerAuth":"","env":"","pkcs11Module":"","pkcs11ModulePin":"","pkcs11ModuleSlotNr":0,"postgresDSN":"","dbMaxOpenConns":"","dbMaxIdleConns":"","dbConnMaxLifetime":"","dbConnMaxIdleTime":"","TCP_addr":"","TLS":false,"TLSCertFile":"","TLSKeyFile":"","CSR_country":"","CSR_organization":"","debug":false,"logTextFormat":false,"certificateServer":"","certificateServerPubKey":"","reloadCertsEveryMinute":false,"kdMaxTotalMemMiB":0,"kdParamMemMiB":0,"kdParamTime":0,"ServerTLSCertFingerprints":null,"DbParams":null,"KdParams":null}`

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
	log.SetLevel(log.FatalLevel) // set log level to FATAL after this test to avoid flooding the terminal
}

func TestConfig_Load_Min(t *testing.T) {
	conf := &Config{}
	err := conf.Load("", "example_config_min.json")
	if err != nil {
		t.Errorf("unable to load configuration: %s", err)
	}
}

func TestConfig_Load_FileNotFound(t *testing.T) {
	conf := &Config{}
	err := conf.Load("", "no_existing_file.json")
	if err == nil {
		t.Errorf("Load returned no error for non-existing file")
	}
}
