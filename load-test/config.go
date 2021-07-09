package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	Url          string
	RegisterAuth string
	Token        map[string]string
}

func (c *Config) Load(filename string) error {
	fileHandle, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	return json.NewDecoder(fileHandle).Decode(c)
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
