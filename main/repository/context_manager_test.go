package repository

import (
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"testing"
)

func TestGetCtxManagerDB(t *testing.T) {
	dbConf, err := getDatabaseConfig()
	if err != nil {
		t.Fatal(err)
	}

	conf := &config.Config{
		PostgresDSN: dbConf.PostgresDSN,
		DbParams:    dbConf.dbParams,
	}

	ctxMngr, err := GetCtxManager(conf)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := ctxMngr.(*DatabaseManager)
	if !ok {
		t.Error("unexpected CtxManager type")
	}

	ctxMngr.Close()
}

func TestGetCtxManagerFile(t *testing.T) {
	conf := &config.Config{}

	expectedErr := "file-based context management is not supported in the current version"

	_, err := GetCtxManager(conf)
	if err == nil {
		t.Fatalf("GetCtxManager did not return expected error for file manager initialization: %s", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Error(err)
	}
}
