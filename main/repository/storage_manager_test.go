package repository

import (
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"testing"
)

func TestGetStorageManagerDB(t *testing.T) {
	dbConf, err := getDatabaseConfig()
	if err != nil {
		t.Fatal(err)
	}

	conf := &config.Config{
		PostgresDSN: dbConf.PostgresDSN,
		DbParams:    dbConf.dbParams,
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
	if err == nil {
		t.Fatalf("GetStorageManager did not return expected error for file manager initialization: %s", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Error(err)
	}
}
