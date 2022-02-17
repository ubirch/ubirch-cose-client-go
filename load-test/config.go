package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	urlpkg "net/url"
)

type Config struct {
	Url          string            `json:"url"`
	RegisterAuth string            `json:"registerAuth"`
	Token        map[string]string `json:"token"`
	CSR          map[string]string `json:"csr"`
	url          *urlpkg.URL
}

func (c *Config) load() error {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})

	flag.Parse()
	if len(*configFile) == 0 {
		*configFile = defaultConfigFile
	}
	log.Infof("loading config: %s", *configFile)

	fileHandle, err := os.Open(filepath.Clean(*configFile))
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

	err = fileHandle.Close()
	if err != nil {
		return err
	}

	c.url, err = urlpkg.Parse(c.Url)
	if err != nil {
		return fmt.Errorf("client base URL could not be parsed: %v", err)
	}

	return nil
}

func (c *Config) persistAuth(id, auth string, csr []byte) error {
	c.Token[id] = auth

	if c.CSR == nil {
		c.CSR = make(map[string]string)
	}
	c.CSR[id] = string(csr)

	fileHandle, err := os.Create(filepath.Clean(*configFile))
	if err != nil {
		return err
	}

	err = json.NewEncoder(fileHandle).Encode(c)
	if err != nil {
		if fileCloseErr := fileHandle.Close(); fileCloseErr != nil {
			log.Error(fileCloseErr)
		}
		return err
	}

	return fileHandle.Close()
}

func (c *Config) initTestIdentities(sender *Sender) (identities map[string]string, err error) {
	identities = make(map[string]string, numberOfTestIDs)

	for uid, auth := range c.Token {
		if auth == "" {
			var csr []byte
			auth, csr, err = sender.register(*c.url, uid, c.RegisterAuth)
			if err != nil {
				return nil, err
			}

			err = c.persistAuth(uid, auth, csr)
			if err != nil {
				return nil, fmt.Errorf("%s: persisting auth token failed: %v (auth token: %s) ", uid, err, auth)
			}
		}

		identities[uid] = auth

		if len(identities) == numberOfTestIDs {
			break
		}
	}

	return identities, nil
}
