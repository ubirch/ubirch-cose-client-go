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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/kelseyhightower/envconfig"

	log "github.com/sirupsen/logrus"
)

const (
	secretLength = 32

	PROD_STAGE = "prod"

	defaultKeyURL      = "https://identity.%s.ubirch.com/api/keyService/v1/pubkey"
	defaultIdentityURL = "https://identity.%s.ubirch.com/api/certs/v1/csr/register"
	//defaultSigningServiceURL = "http://localhost:8080"

	identitiesFileName = "identities.json"

	defaultCSRCountry      = "DE"
	defaultCSROrganization = "ubirch GmbH"

	defaultTCPAddr = ":8080"

	defaultTLSCertFile = "cert.pem"
	defaultTLSKeyFile  = "key.pem"
)

type Config struct {
	Tokens                  map[uuid.UUID]string `json:"tokens"`
	SecretBase64            string               `json:"secret32" envconfig:"SECRET32"`                                 // 32 byte secret used to encrypt the key store (mandatory)
	RegisterAuth            string               `json:"registerAuth" envconfig:"REGISTERAUTH"`                         // auth token needed for new identity registration
	Env                     string               `json:"env"`                                                           // the ubirch backend environment [dev, demo, prod], defaults to 'prod'
	DsnInitContainer        bool                 `json:"DSN_InitDb" envconfig:"DSN_INITDB"`                             // flag to determine if a database should be used for context management
	DsnHost                 string               `json:"DSN_Host" envconfig:"DSN_HOST"`                                 // database host name
	DsnUser                 string               `json:"DSN_User" envconfig:"DSN_USER"`                                 // database user name
	DsnPassword             string               `json:"DSN_Password" envconfig:"DSN_PASSWORD"`                         // database password
	DsnDb                   string               `json:"DSN_Database" envconfig:"DSN_DATABASE"`                         // database name
	TCP_addr                string               `json:"TCP_addr"`                                                      // the TCP address for the server to listen on, in the form "host:port"
	TLS                     bool                 `json:"TLS"`                                                           // enable serving HTTPS endpoints, defaults to 'false'
	TLS_CertFile            string               `json:"TLSCertFile"`                                                   // filename of TLS certificate file name, defaults to "cert.pem"
	TLS_KeyFile             string               `json:"TLSKeyFile"`                                                    // filename of TLS key file name, defaults to "key.pem"
	CSR_Country             string               `json:"CSR_country"`                                                   // subject country for public key Certificate Signing Requests
	CSR_Organization        string               `json:"CSR_organization"`                                              // subject organization for public key Certificate Signing Requests
	Debug                   bool                 `json:"debug"`                                                         // enable extended debug output, defaults to 'false'
	LogTextFormat           bool                 `json:"logTextFormat"`                                                 // log in text format for better human readability, default format is JSON
	CertificateServer       string               `json:"certificateServer" envconfig:"CERTIFICATE_SERVER"`              // public key certificate list server URL
	CertificateServerPubKey string               `json:"certificateServerPubKey" envconfig:"CERTIFICATE_SERVER_PUBKEY"` // public key for verification of the public key certificate list signature server URL
	ReloadCertsEveryMinute  bool                 `json:"reloadCertsEveryMinute" envconfig:"RELOAD_CERTS_EVERY_MINUTE"`  // setting to make the service request the public key certificate list once a minute
	KeyService              string               // key service URL
	IdentityService         string               // identity service URL
	//SigningService   string               // signing service URL
	configDir   string // directory where config and protocol ctx are stored
	secretBytes []byte // the decoded key store secret
}

func (c *Config) Load(configDir string, filename string) error {
	c.configDir = configDir

	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_SECRET env variable set.
	var err error
	if os.Getenv("UBIRCH_SECRET32") != "" {
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

	c.secretBytes, err = base64.StdEncoding.DecodeString(c.SecretBase64)
	if err != nil {
		return fmt.Errorf("unable to decode base64 encoded secret (%s): %v", c.SecretBase64, err)
	}

	err = c.checkMandatory()
	if err != nil {
		return err
	}

	c.setDefaultCSR()
	c.setDefaultTLS()
	return c.setDefaultURLs()
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
	if len(c.secretBytes) != secretLength {
		return fmt.Errorf("secret for key encryption ('secret32') length must be %d bytes (is %d)", secretLength, len(c.secretBytes))
	}

	if len(c.RegisterAuth) == 0 {
		return fmt.Errorf("auth token for identity registration ('registerAuth') wasn't set")
	}

	if c.CertificateServer == "" {
		return fmt.Errorf("missing 'certificateServer' in configuration")
	}

	if c.CertificateServerPubKey == "" {
		return fmt.Errorf("missing 'certificateServerPubKey' in configuration")
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

func (c *Config) setDefaultURLs() error {
	if c.Env == "" {
		c.Env = PROD_STAGE
	}

	if c.KeyService == "" {
		c.KeyService = fmt.Sprintf(defaultKeyURL, c.Env)
	} else {
		c.KeyService = strings.TrimSuffix(c.KeyService, "/mpack")
	}

	if c.IdentityService == "" {
		c.IdentityService = fmt.Sprintf(defaultIdentityURL, c.Env)
	}

	//if c.SigningService == "" {
	//	c.SigningService = defaultSigningServiceURL
	//}

	log.Infof("UBIRCH backend environment: %s", c.Env)
	log.Debugf(" - Key Service:      %s", c.KeyService)
	log.Debugf(" - Identity Service: %s", c.IdentityService)
	//log.Debugf(" - Signing Service:  %s", c.SigningService)

	return nil
}

// loadIdentitiesFile loads identities from the identities JSON file.
func (c *Config) loadIdentitiesFile(identities *[]*Identity) error {
	identitiesFile := filepath.Join(c.configDir, identitiesFileName)

	// if file does not exist, return right away
	if _, err := os.Stat(identitiesFile); os.IsNotExist(err) {
		return nil
	}

	fileHandle, err := os.Open(identitiesFile)
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	err = json.NewDecoder(fileHandle).Decode(identities)
	if err != nil {
		return err
	}

	log.Infof("found %d entries in file %s", len(*identities), identitiesFile)

	tokenAlreadyExists := make(map[string]bool, len(*identities))

	for _, i := range *identities {
		//if len(i.Tenant) == 0 {
		//	return fmt.Errorf("%s: empty tenant field", i.Uid)
		//}
		//if len(i.Category) == 0 {
		//	return fmt.Errorf("%s: empty category field", i.Uid)
		//}
		if i.Uid == uuid.Nil {
			return fmt.Errorf("%s: empty UUID", i.Uid)
		}
		log.Debugf("  - %s", i.Uid)

		if len(i.AuthToken) == 0 {
			return fmt.Errorf("%s: empty auth token field", i.Uid)
		}
		if tokenAlreadyExists[i.AuthToken] {
			return fmt.Errorf("%s: can not use same token for multiple identities", i.Uid)
		} else {
			tokenAlreadyExists[i.AuthToken] = true
		}
	}

	return nil
}

func (c *Config) loadTokens(identities *[]*Identity) error {
	log.Infof("found %d UUIDs in tokens map", len(c.Tokens))

	for uid, token := range c.Tokens {
		log.Debugf("  - %s", uid)

		if len(token) == 0 {
			return fmt.Errorf("%s: empty auth token", uid)
		}

		i := Identity{
			Uid:       uid,
			AuthToken: token,
		}

		*identities = append(*identities, &i)
	}

	return nil
}
