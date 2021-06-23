package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestGetCtxManagerDB(t *testing.T) {
	fileHandle, err := os.Open("config.json")
	if err != nil {
		t.Fatal(err)
	}
	defer fileHandle.Close()

	c := &dbConfig{}
	err = json.NewDecoder(fileHandle).Decode(c)
	if err != nil {
		t.Fatal(err)
	}

	conf := &Config{
		PostgresDSN: c.PostgresDSN,
		dbParams: DatabaseParams{
			MaxOpenConns:    5,
			MaxIdleConns:    5,
			ConnMaxLifetime: 2 * time.Minute,
			ConnMaxIdleTime: 1 * time.Minute,
		},
	}

	ctxMngr, err := GetCtxManager(conf)
	if err != nil {
		t.Error(err)
	}

	_, ok := ctxMngr.(*DatabaseManager)
	if !ok {
		t.Error("unexpected CtxManager type")
	}

	ctxMngr.Close()
}

func TestGetCtxManagerFile(t *testing.T) {
	conf := &Config{}

	expectedErr := "file-based context management is not supported in the current version"

	_, err := GetCtxManager(conf)
	if err == nil {
		t.Fatalf("GetCtxManager did not return expected error for file manager initialization: %s", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Error(err)
	}
}
