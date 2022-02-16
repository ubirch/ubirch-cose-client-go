package config

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	log "github.com/sirupsen/logrus"
)

const (
	expectedConfig = `{"registerAuth":"","env":"","pkcs11Module":"","pkcs11ModulePin":"","pkcs11ModuleSlotNr":0,"postgresDSN":"","dbMaxOpenConns":"","dbMaxIdleConns":"","dbConnMaxLifetime":"","dbConnMaxIdleTime":"","TCP_addr":"","TLS":false,"TLSCertFile":"","TLSKeyFile":"","CSR_country":"","CSR_organization":"","debug":false,"logTextFormat":false,"certificateServer":"","certificateServerPubKey":"","reloadCertsEveryMinute":false,"ignoreUnknownCerts":false,"certifyApiUrl":"","certifyApiAuth":"","kdMaxTotalMemMiB":0,"kdParamMemMiB":0,"kdParamTime":0,"kdParamParallelism":0,"kdParamKeyLen":0,"kdParamSaltLen":0,"kdUpdateParams":false,"requestLimit":0,"requestBacklogLimit":0,"IsDevelopment":false,"ServerTLSCertFingerprints":null,"DbParams":null}`
)

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

	assert.Equal(t, string(configBytes), string(jsonBytes))
}

func TestConfig_Load_Full(t *testing.T) {
	conf := &Config{}
	err := conf.Load("", "example_config.json")
	require.NoError(t, err)

	log.SetLevel(log.FatalLevel) // set log level to FATAL after this test to avoid flooding the terminal
}

func TestConfig_Load_Min(t *testing.T) {
	conf := &Config{}
	err := conf.Load("", "example_config_min.json")
	require.NoError(t, err)
}

func TestConfig_Load_FileNotFound(t *testing.T) {
	conf := &Config{}
	err := conf.Load("", "no_existing_file.json")
	assert.Error(t, err)
}

func TestConfig_Load_loadEnv(t *testing.T) {
	err := os.Setenv("UBIRCH_REGISTERAUTH", "1234")
	require.NoError(t, err)

	conf := &Config{}
	err = conf.Load("", "")
	assert.EqualError(t, err, "missing 'certificateServer' / 'UBIRCH_CERTIFICATE_SERVER' in configuration")
}

func TestConfig_loadEnv(t *testing.T) {
	const testRegisterAuth = "1234"

	err := os.Setenv("UBIRCH_REGISTERAUTH", testRegisterAuth)
	require.NoError(t, err)

	conf := &Config{}
	err = conf.loadEnv()
	require.NoError(t, err)
	assert.Equal(t, testRegisterAuth, conf.RegisterAuth)
}

func TestConfig_checkMandatory(t *testing.T) {
	conf := &Config{}

	err := conf.checkMandatory()
	assert.EqualError(t, err, "missing 'registerAuth' / 'UBIRCH_REGISTERAUTH' in configuration")

	conf.RegisterAuth = "1234"

	err = conf.checkMandatory()
	assert.EqualError(t, err, "missing 'certificateServer' / 'UBIRCH_CERTIFICATE_SERVER' in configuration")

	conf.CertificateServer = "certs.com"

	err = conf.checkMandatory()
	assert.EqualError(t, err, "missing 'certificateServerPubKey' / 'UBIRCH_CERTIFICATE_SERVER_PUBKEY' in configuration")

	conf.CertificateServerPubKey = "certs.com/pub"

	err = conf.checkMandatory()
	assert.EqualError(t, err, "missing 'certifyApiUrl' / 'UBIRCH_CERTIFY_API_URL' in configuration")

	conf.CertifyApiUrl = "certify.com"

	err = conf.checkMandatory()
	assert.EqualError(t, err, "missing 'certifyApiAuth' / 'UBIRCH_CERTIFY_API_AUTH' in configuration")

	conf.CertifyApiAuth = "password123"

	err = conf.checkMandatory()
	assert.EqualError(t, err, "missing 'pkcs11ModulePin' / 'UBIRCH_PKCS11_MODULE_PIN' in configuration")

	conf.PKCS11ModulePin = "12345"

	err = conf.checkMandatory()
	require.NoError(t, err)
	assert.Equal(t, PROD_STAGE, conf.Env)
}
