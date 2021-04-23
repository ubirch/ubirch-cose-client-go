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

	"github.com/google/uuid"
	"github.com/kelseyhightower/envconfig"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const (
	secretLength = 16
	tokenLength  = 32

	defaultTCPAddr = ":8081"

	defaultTLSCertFile = "cert.pem"
	defaultTLSKeyFile  = "key.pem"
)

type Config struct {
	SecretBase64  string               `json:"secret"`        // secret used to encrypt the key store (mandatory)
	Keys          map[uuid.UUID]string `json:"keys"`          // maps UUIDs to signing keys (mandatory)
	Tokens        map[uuid.UUID]string `json:"tokens"`        // maps UUIDs to auth tokens (mandatory)
	TCP_addr      string               `json:"TCP_addr"`      // the TCP address for the server to listen on, in the form "host:port", defaults to ":8081"
	TLS           bool                 `json:"TLS"`           // enable serving HTTPS endpoints, defaults to 'false'
	TLS_CertFile  string               `json:"TLSCertFile"`   // filename of TLS certificate file name, defaults to "cert.pem"
	TLS_KeyFile   string               `json:"TLSKeyFile"`    // filename of TLS key file name, defaults to "key.pem"
	Debug         bool                 `json:"debug"`         // enable extended debug output, defaults to 'false'
	LogTextFormat bool                 `json:"logTextFormat"` // log in text format for better human readability, default format is JSON
	secretBytes   []byte               // the decoded key store secret (set automatically)
	configDir     string               // directory where config and protocol ctx are stored (set automatically)
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
	if len(c.secretBytes) != secretLength {
		return fmt.Errorf("secret length must be %d bytes (is %d)", secretLength, len(c.secretBytes))
	}

	if len(c.Keys) == 0 {
		return fmt.Errorf("no signing keys")
	}

	// make sure there is an auth token for each key and check length
	for uid := range c.Keys {
		token, found := c.Tokens[uid]
		if !found {
			return fmt.Errorf("no auth token for %s", uid)
		}

		tokenBytes, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			return fmt.Errorf("unable to decode base64 encoded token for %s: %s: %v", uid, token, err)
		}

		if len(tokenBytes) != tokenLength {
			return fmt.Errorf("%s: token length must be %d bytes (is %d)", uid, tokenLength, len(tokenBytes))
		}
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

func injectKeys(c ubirch.Crypto, keys map[uuid.UUID]string) error {
	for uid, key := range keys {
		keyBytes, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return fmt.Errorf("unable to decode private key for %s: %s: %v", uid, key, err)
		}
		err = c.SetKey(uid, keyBytes)
		if err != nil {
			return fmt.Errorf("unable to inject key to keystore: %v", err)
		}
	}

	return nil
}
