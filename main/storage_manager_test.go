package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
)

func TestGetStorageManagerDB(t *testing.T) {
	conf, err := getDatabaseConfig()
	if err != nil {
		t.Fatal(err)
	}

	storageMngr, err := GetStorageManager(conf)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := storageMngr.(*DatabaseManager)
	if !ok {
		t.Error("unexpected StorageManager type")
	}

	storageMngr.Close()
}

func TestGetStorageManagerFile(t *testing.T) {
	conf := &config.Config{}

	expectedErr := "file-based context management is not supported in the current version"

	_, err := GetStorageManager(conf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), expectedErr)
}
