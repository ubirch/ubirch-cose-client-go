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

package main

import (
	"crypto/sha256"
	"crypto/x509"
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
	ProdStage = "prod"

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

	defaultPKCS11Module = "libcs_pkcs11_R3.so"
)

type Config struct {
	RegisterAuth              string `json:"registerAuth" envconfig:"REGISTERAUTH"`                         // auth token needed for new identity registration
	Env                       string `json:"env" envconfig:"ENV"`                                           // the ubirch backend environment [dev, demo, prod], defaults to 'prod'
	PKCS11Module              string `json:"pkcs11Module" envconfig:"PKCS11_MODULE"`                        //
	PKCS11ModulePin           string `json:"pkcs11ModulePin" envconfig:"PKCS11_MODULE_PIN"`                 //
	PKCS11ModuleSlotNr        int    `json:"pkcs11ModuleSlotNr" envconfig:"PKCS11_MODULE_SLOT_NR"`          //
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
	serverTLSCertFingerprints map[string][32]byte
	configDir                 string // directory where config and protocol ctx are stored
	dbParams                  *DatabaseParams
}

func (c *Config) Load(configDir, filename string) error {
	c.configDir = configDir

	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_SECRET env variable set.
	var err error
	if os.Getenv("UBIRCH_REGISTERAUTH") != "" {
		err = c.loadEnv()
	} else {
		err = c.loadFile(filename)
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

	err = c.checkMandatory()
	if err != nil {
		return err
	}

	err = c.loadServerTLSCertificates()
	if err != nil {
		return fmt.Errorf("loading TLS certificates failed: %v", err)
	}

	c.setDefaultHSM()
	c.setDefaultCSR()
	c.setDefaultTLS()
	return c.setDbParams()
}

// loadEnv reads the configuration from environment variables
func (c *Config) loadEnv() error {
	log.Infof("loading configuration from environment variables")
	return envconfig.Process("ubirch", c)
}

// LoadFile reads the configuration from a json file
func (c *Config) loadFile(filename string) error {
	configFile := filepath.Join(c.configDir, filename)
	log.Infof("loading configuration from file: %s", configFile)

	fileHandle, err := os.Open(configFile)
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	return json.NewDecoder(fileHandle).Decode(c)
}

func (c *Config) checkMandatory() error {
	if len(c.RegisterAuth) == 0 {
		return fmt.Errorf("auth token for identity registration ('registerAuth') wasn't set")
	}

	if len(c.CertificateServer) == 0 {
		return fmt.Errorf("missing 'certificateServer' in configuration")
	}

	if len(c.CertificateServerPubKey) == 0 {
		return fmt.Errorf("missing 'certificateServerPubKey' in configuration")
	}

	if len(c.PKCS11ModulePin) == 0 {
		return fmt.Errorf("missing 'pkcs11ModulePin / UBIRCH_PKCS11_MODULE_PIN' in configuration")
	}

	if len(c.Env) == 0 {
		c.Env = ProdStage
	}

	return nil
}

func (c *Config) setDefaultHSM() {
	if len(c.PKCS11Module) == 0 {
		c.PKCS11Module = defaultPKCS11Module
	}
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

func (c *Config) setDefaultTLS() {
	if c.TCP_addr == "" {
		c.TCP_addr = defaultTCPAddr
	}
	log.Debugf("TCP address: %s", c.TCP_addr)

	if c.TLS {
		log.Debug("TLS enabled")

		if c.TLS_CertFile == "" {
			c.TLS_CertFile = defaultTLSCertFile
		}
		c.TLS_CertFile = filepath.Join(c.configDir, c.TLS_CertFile)
		log.Debugf(" - Cert: %s", c.TLS_CertFile)

		if c.TLS_KeyFile == "" {
			c.TLS_KeyFile = defaultTLSKeyFile
		}
		c.TLS_KeyFile = filepath.Join(c.configDir, c.TLS_KeyFile)
		log.Debugf(" -  Key: %s", c.TLS_KeyFile)
	}
}

func (c *Config) setDbParams() error {
	c.dbParams = &DatabaseParams{}

	if c.DbMaxOpenConns == "" {
		c.dbParams.MaxOpenConns = defaultDbMaxOpenConns
	} else {
		i, err := strconv.Atoi(c.DbMaxOpenConns)
		if err != nil {
			return fmt.Errorf("failed to set DB parameter MaxOpenConns: %v", err)
		}
		c.dbParams.MaxOpenConns = i
	}

	if c.DbMaxIdleConns == "" {
		c.dbParams.MaxIdleConns = defaultDbMaxIdleConns
	} else {
		i, err := strconv.Atoi(c.DbMaxIdleConns)
		if err != nil {
			return fmt.Errorf("failed to set DB parameter MaxIdleConns: %v", err)
		}
		c.dbParams.MaxIdleConns = i
	}

	if c.DbConnMaxLifetime == "" {
		c.dbParams.ConnMaxLifetime = defaultDbConnMaxLifetime * time.Minute
	} else {
		i, err := strconv.Atoi(c.DbConnMaxLifetime)
		if err != nil {
			return fmt.Errorf("failed to set DB parameter ConnMaxLifetime: %v", err)
		}
		c.dbParams.ConnMaxLifetime = time.Duration(i) * time.Minute
	}

	if c.DbConnMaxIdleTime == "" {
		c.dbParams.ConnMaxIdleTime = defaultDbConnMaxIdleTime * time.Minute
	} else {
		i, err := strconv.Atoi(c.DbConnMaxIdleTime)
		if err != nil {
			return fmt.Errorf("failed to set DB parameter ConnMaxIdleTime: %v", err)
		}
		c.dbParams.ConnMaxIdleTime = time.Duration(i) * time.Minute
	}

	return nil
}

func (c *Config) loadServerTLSCertificates() error {
	serverTLSCertFile := filepath.Join(c.configDir, fmt.Sprintf(tlsCertsFileName, c.Env))

	fileHandle, err := os.Open(serverTLSCertFile)
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	serverTLSCertBuffer := make(map[string][]byte)

	err = json.NewDecoder(fileHandle).Decode(&serverTLSCertBuffer)
	if err != nil {
		return err
	}

	if len(serverTLSCertBuffer) == 0 {
		return fmt.Errorf("no TLS certificates found in file %s", serverTLSCertFile)
	}
	log.Infof("found %d entries in file %s", len(serverTLSCertBuffer), serverTLSCertFile)

	c.serverTLSCertFingerprints = make(map[string][32]byte)

	for host, cert := range serverTLSCertBuffer {
		x509cert, err := x509.ParseCertificate(cert)
		if err != nil {
			log.Errorf("parsing x.509 certificate for host %s failed: %v, expected certificate format: base64 encoded ASN.1 DER", host, err)
			continue
		}

		fingerprint := sha256.Sum256(x509cert.RawSubjectPublicKeyInfo)
		c.serverTLSCertFingerprints[host] = fingerprint
	}

	return nil
}
