package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

type Config struct {
	Url          string
	RegisterAuth string
	Token        map[string]string
}

func (c *Config) Load(filename string) error {
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

func (c *Config) getTestIdentities() map[string]string {
	testIdentities := make(map[string]string, numberOfTestIDs)

	for uid, auth := range c.Token {
		testIdentities[uid] = auth
		if len(testIdentities) == numberOfTestIDs {
			break
		}
	}

	return testIdentities
}
