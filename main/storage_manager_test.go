package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
)

func TestGetStorageManagerDB(t *testing.T) {
	conf, err := getDatabaseConfig()
	require.NoError(t, err)

	storageMngr, err := GetStorageManager(conf)
	require.NoError(t, err)

	_, ok := storageMngr.(*DatabaseManager)
	assert.Truef(t, ok, "unexpected StorageManager type")

	storageMngr.Close()
}

func TestGetStorageManagerFile(t *testing.T) {
	conf := &config.Config{}

	expectedErr := "file-based context management is not supported in the current version"

	_, err := GetStorageManager(conf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), expectedErr)
}
