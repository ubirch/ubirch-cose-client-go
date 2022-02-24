// Copyright (c) 2021 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kelseyhightower/envconfig"

	log "github.com/sirupsen/logrus"
)

const (
	secretLength = 32

	DEV_STAGE  = "dev"
	DEMO_STAGE = "demo"
	QA_STAGE   = "qa"
	PROD_STAGE = "prod"

	tlsCertsFileName = "%s_ubirch_tls_certs.json"

	defaultCSRCountry      = "DE"
	defaultCSROrganization = "ubirch GmbH"

	defaultTCPAddr = ":8080"

	defaultTLSCertFile = "cert.pem"
	defaultTLSKeyFile  = "key.pem"

	defaultDbMaxOpenConns    = 10
	defaultDbMaxIdleConns    = 10
	defaultDbConnMaxLifetime = 10
	defaultDbConnMaxIdleTime = 1
)

type Config struct {
	SecretBase64              string `json:"secret32" envconfig:"SECRET32"`                                 // 32 byte secret used to encrypt the key store (mandatory)
	RegisterAuth              string `json:"registerAuth" envconfig:"REGISTERAUTH"`                         // auth token needed for new identity registration
	Env                       string `json:"env" envconfig:"ENV"`                                           // the ubirch backend environment [dev, demo, prod], defaults to 'prod'
	PostgresDSN               string `json:"postgresDSN" envconfig:"POSTGRES_DSN"`                          // data source name for postgres database
	DbMaxOpenConns            string `json:"dbMaxOpenConns" envconfig:"DB_MAX_OPEN_CONNS"`                  // maximum number of open connections to the database
	DbMaxIdleConns            string `json:"dbMaxIdleConns" envconfig:"DB_MAX_IDLE_CONNS"`                  // maximum number of connections in the idle connection pool
	DbConnMaxLifetime         string `json:"dbConnMaxLifetime" envconfig:"DB_CONN_MAX_LIFETIME"`            // maximum amount of time in minutes a connection may be reused
	DbConnMaxIdleTime         string `json:"dbConnMaxIdleTime" envconfig:"DB_CONN_MAX_IDLE_TIME"`           // maximum amount of time in minutes a connection may be idle
	TCP_addr                  string `json:"TCP_addr"`                                                      // the TCP address for the server to listen on, in the form "host:port"
	TLS                       bool   `json:"TLS"`                                                           // enable serving HTTPS endpoints, defaults to 'false'
	TLS_CertFile              string `json:"TLSCertFile"`                                                   // filename of TLS certificate file name, defaults to "cert.pem"
	TLS_KeyFile               string `json:"TLSKeyFile"`                                                    // filename of TLS key file name, defaults to "key.pem"
	CSR_Country               string `json:"CSR_country"`                                                   // subject country for public key Certificate Signing Requests
	CSR_Organization          string `json:"CSR_organization"`                                              // subject organization for public key Certificate Signing Requests
	Debug                     bool   `json:"debug"`                                                         // enable extended debug output, defaults to 'false'
	LogTextFormat             bool   `json:"logTextFormat"`                                                 // log in text format for better human readability, default format is JSON
	CertificateServer         string `json:"certificateServer" envconfig:"CERTIFICATE_SERVER"`              // public key certificate list server URL
	CertificateServerPubKey   string `json:"certificateServerPubKey" envconfig:"CERTIFICATE_SERVER_PUBKEY"` // public key for verification of the public key certificate list signature server URL
	ReloadCertsEveryMinute    bool   `json:"reloadCertsEveryMinute" envconfig:"RELOAD_CERTS_EVERY_MINUTE"`  // setting to make the service request the public key certificate list once a minute
	IgnoreUnknownCerts        bool   `json:"ignoreUnknownCerts" envconfig:"IGNORE_UNKNOWN_CERTS"`           // if set to 'false', a warning will be logged in case a certificate for an unknown public key is found in the public key certificate list
	CertifyApiUrl             string `json:"certifyApiUrl" envconfig:"CERTIFY_API_URL"`                     // URL of the certify API
	CertifyApiAuth            string `json:"certifyApiAuth" envconfig:"CERTIFY_API_AUTH"`                   // auth token for the seal registration endpoint of the certify API
	IsDevelopment             bool   // (set automatically depending on env) flag signifying if the environment is development (true) or productive (false)
	ServerTLSCertFingerprints map[string][32]byte
	SecretBytes               []byte // the decoded key store secret
	DbParams                  *DatabaseParams
}

type DatabaseParams struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

func (c *Config) Load(configDir, filename string) error {
	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_SECRET env variable set.
	var err error
	if os.Getenv("UBIRCH_REGISTERAUTH") != "" {
		err = c.loadEnv()
	} else {
		err = c.loadFile(filepath.Join(configDir, filename))
	}
	if err != nil {
		return err
	}

	if c.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if c.LogTextFormat {
		log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})
	}

	c.secretBytes, err = base64.StdEncoding.DecodeString(c.SecretBase64)
	if err != nil {
		return fmt.Errorf("unable to decode base64 encoded secret (%s): %v", c.SecretBase64, err)
	}

	err = c.checkMandatory()
	if err != nil {
		return err
	}

	err = c.LoadServerTLSCertificates(filepath.Join(configDir, fmt.Sprintf(tlsCertsFileName, c.Env)))
	if err != nil {
		return fmt.Errorf("loading TLS certificates failed: %v", err)
	}

	c.setDefaultCSR()
	c.setDefaultTLS(configDir)
	return c.SetDbParams()
}

// loadEnv reads the configuration from environment variables
func (c *Config) loadEnv() error {
	log.Infof("loading configuration from environment variables")
	return envconfig.Process("ubirch", c)
}

// LoadFile reads the configuration from a json file
func (c *Config) loadFile(filename string) error {
	log.Infof("loading configuration from file: %s", filename)

	fileHandle, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return err
	}

	err = json.NewDecoder(fileHandle).Decode(c)
	if err != nil {
		if fileCloseErr := fileHandle.Close(); fileCloseErr != nil {
			log.Error(fileCloseErr)
		}
		return err
	}

	return fileHandle.Close()
}

func (c *Config) checkMandatory() error {
	if len(c.secretBytes) != secretLength {
		return fmt.Errorf("secret for key encryption ('secret32') length must be %d bytes (is %d)", secretLength, len(c.secretBytes))
	}

	if len(c.RegisterAuth) == 0 {
		return fmt.Errorf("missing 'registerAuth' / 'UBIRCH_REGISTERAUTH' in configuration")
	}

	if len(c.CertificateServer) == 0 {
		return fmt.Errorf("missing 'certificateServer' / 'UBIRCH_CERTIFICATE_SERVER' in configuration")
	}

	if len(c.CertificateServerPubKey) == 0 {
		return fmt.Errorf("missing 'certificateServerPubKey' / 'UBIRCH_CERTIFICATE_SERVER_PUBKEY' in configuration")
	}

	if len(c.CertifyApiUrl) == 0 {
		return fmt.Errorf("missing 'certifyApiUrl' / 'UBIRCH_CERTIFY_API_URL' in configuration")
	}

	if len(c.CertifyApiAuth) == 0 {
		return fmt.Errorf("missing 'certifyApiAuth' / 'UBIRCH_CERTIFY_API_AUTH' in configuration")
	}

	if len(c.Env) == 0 {
		c.Env = PROD_STAGE
	}

	// set flag for non-production environments
	if c.Env == DEV_STAGE || c.Env == DEMO_STAGE || c.Env == QA_STAGE {
		c.IsDevelopment = true
	}

	return nil
}

func (c *Config) setDefaultCSR() {
	if c.CSR_Country == "" {
		c.CSR_Country = defaultCSRCountry
	}
	log.Debugf("CSR Subject Country: %s", c.CSR_Country)

	if c.CSR_Organization == "" {
		c.CSR_Organization = defaultCSROrganization
	}
	log.Debugf("CSR Subject Organization: %s", c.CSR_Organization)
}

func (c *Config) setDefaultTLS(configDir string) {
	if c.TCP_addr == "" {
		c.TCP_addr = defaultTCPAddr
	}
	log.Debugf("TCP address: %s", c.TCP_addr)

	if c.TLS {
		log.Debug("TLS enabled")

		if c.TLS_CertFile == "" {
			c.TLS_CertFile = defaultTLSCertFile
		}
		c.TLS_CertFile = filepath.Join(configDir, c.TLS_CertFile)
		log.Debugf(" - Cert: %s", c.TLS_CertFile)

		if c.TLS_KeyFile == "" {
			c.TLS_KeyFile = defaultTLSKeyFile
		}
		c.TLS_KeyFile = filepath.Join(configDir, c.TLS_KeyFile)
		log.Debugf(" -  Key: %s", c.TLS_KeyFile)
	}
}

func (c *Config) SetDbParams() error {
	c.DbParams = &DatabaseParams{}

	if c.DbMaxOpenConns == "" {
		c.DbParams.MaxOpenConns = defaultDbMaxOpenConns
	} else {
		i, err := strconv.Atoi(c.DbMaxOpenConns)
		if err != nil {
			return fmt.Errorf("failed to set DB parameter MaxOpenConns: %v", err)
		}
		c.DbParams.MaxOpenConns = i
	}

	if c.DbMaxIdleConns == "" {
		c.DbParams.MaxIdleConns = defaultDbMaxIdleConns
	} else {
		i, err := strconv.Atoi(c.DbMaxIdleConns)
		if err != nil {
			return fmt.Errorf("failed to set DB parameter MaxIdleConns: %v", err)
		}
		c.DbParams.MaxIdleConns = i
	}

	if c.DbConnMaxLifetime == "" {
		c.DbParams.ConnMaxLifetime = defaultDbConnMaxLifetime * time.Minute
	} else {
		i, err := strconv.Atoi(c.DbConnMaxLifetime)
		if err != nil {
			return fmt.Errorf("failed to set DB parameter ConnMaxLifetime: %v", err)
		}
		c.DbParams.ConnMaxLifetime = time.Duration(i) * time.Minute
	}

	if c.DbConnMaxIdleTime == "" {
		c.DbParams.ConnMaxIdleTime = defaultDbConnMaxIdleTime * time.Minute
	} else {
		i, err := strconv.Atoi(c.DbConnMaxIdleTime)
		if err != nil {
			return fmt.Errorf("failed to set DB parameter ConnMaxIdleTime: %v", err)
		}
		c.DbParams.ConnMaxIdleTime = time.Duration(i) * time.Minute
	}

	return nil
}

func (c *Config) LoadServerTLSCertificates(serverTLSCertFile string) error {
	fileHandle, err := os.Open(filepath.Clean(serverTLSCertFile))
	if err != nil {
		return err
	}

	serverTLSCertBuffer := make(map[string][]byte)

	err = json.NewDecoder(fileHandle).Decode(&serverTLSCertBuffer)
	if err != nil {
		if fileCloseErr := fileHandle.Close(); fileCloseErr != nil {
			log.Error(fileCloseErr)
		}
		return err
	}

	err = fileHandle.Close()
	if err != nil {
		return err
	}

	if len(serverTLSCertBuffer) == 0 {
		return fmt.Errorf("no TLS certificates found in file %s", serverTLSCertFile)
	}
	log.Infof("found %d entries in file %s", len(serverTLSCertBuffer), serverTLSCertFile)

	c.ServerTLSCertFingerprints = make(map[string][32]byte)

	for host, cert := range serverTLSCertBuffer {
		x509cert, err := x509.ParseCertificate(cert)
		if err != nil {
			log.Errorf("parsing x.509 certificate for host %s failed: %v, expected certificate format: base64 encoded ASN.1 DER", host, err)
			continue
		}

		fingerprint := sha256.Sum256(x509cert.RawSubjectPublicKeyInfo)
		c.ServerTLSCertFingerprints[host] = fingerprint
	}

	return nil
}
