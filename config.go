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

	"github.com/kelseyhightower/envconfig"

	log "github.com/sirupsen/logrus"
)

const (
	defaultTCPAddr = ":8081"

	defaultTLSCertFile = "cert.pem"
	defaultTLSKeyFile  = "key.pem"
)

type Config struct {
	SecretBase64  string            `json:"secret"`        // secret used to encrypt the key store (mandatory)
	Keys          map[string]string `json:"keys"`          // maps UUIDs to signing keys (mandatory)
	Tokens        map[string]string `json:"tokens"`        // maps UUIDs to auth tokens (mandatory)
	TCP_addr      string            `json:"TCP_addr"`      // the TCP address for the server to listen on, in the form "host:port", defaults to ":8081"
	TLS           bool              `json:"TLS"`           // enable serving HTTPS endpoints, defaults to 'false'
	TLS_CertFile  string            `json:"TLSCertFile"`   // filename of TLS certificate file name, defaults to "cert.pem"
	TLS_KeyFile   string            `json:"TLSKeyFile"`    // filename of TLS key file name, defaults to "key.pem"
	Debug         bool              `json:"debug"`         // enable extended debug output, defaults to 'false'
	LogTextFormat bool              `json:"logTextFormat"` // log in text format for better human readability, default format is JSON
	secretBytes   []byte            // the decoded key store secret (set automatically)
	configDir     string            // directory where config and protocol ctx are stored (set automatically)
}

func (c *Config) Load(configDir string, filename string) error {
	c.configDir = configDir

	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_SECRET env variable set.
	var err error
	if os.Getenv("UBIRCH_SECRET") != "" {
		err = c.loadEnv()
	} else {
		err = c.loadFile(filename)
	}
	if err != nil {
		return err
	}

	c.secretBytes, err = base64.StdEncoding.DecodeString(c.SecretBase64)
	if err != nil {
		return fmt.Errorf("unable to decode base64 encoded secret (%s): %v", c.SecretBase64, err)
	}

	err = c.checkMandatory()
	if err != nil {
		return err
	}

	if c.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if c.LogTextFormat {
		log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})
	}

	c.setDefaultTLS()

	return nil
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
	if len(c.Keys) == 0 {
		return fmt.Errorf("no signing keys")
	}

	// todo make sure there is a token for each key and check len(token)

	if len(c.secretBytes) != 16 {
		return fmt.Errorf("secret length must be 16 bytes (is %d)", len(c.secretBytes))
	}

	return nil
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
