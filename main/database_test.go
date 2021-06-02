package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/uuid"
)

const (
	TestTableName = "test_cose_identity"
)

var (
	testIdentity = generateRandomIdentity()
)

func TestDatabaseManager(t *testing.T) {
	dbManager, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUp(t, dbManager)

	// check not exists
	exists, err := dbManager.ExistsPublicKey(testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Errorf("dbManager.ExistsPublicKey returned TRUE")
	}

	exists, err = dbManager.ExistsPrivateKey(testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Errorf("dbManager.ExistsPrivateKey returned TRUE")
	}

	exists, err = dbManager.ExistsUuidForPublicKey(testIdentity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("dbManager.ExistsUuidForPublicKey returned TRUE")
	}

	// store identity
	tx, err := dbManager.StartTransaction(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = dbManager.StoreNewIdentity(tx, *testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	err = dbManager.CloseTransaction(tx, Commit)
	if err != nil {
		t.Fatal(err)
	}

	// check exists
	exists, err = dbManager.ExistsPublicKey(testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Errorf("dbManager.ExistsPublicKey returned FALSE")
	}

	exists, err = dbManager.ExistsPrivateKey(testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Errorf("dbManager.ExistsPrivateKey returned FALSE")
	}

	exists, err = dbManager.ExistsUuidForPublicKey(testIdentity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("public key not found")
	}

	// get attributes
	auth, err := dbManager.GetAuthToken(testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}
	if auth != testIdentity.AuthToken {
		t.Error("GetAuthToken returned unexpected value")
	}

	priv, err := dbManager.GetPrivateKey(testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv, testIdentity.PrivateKey) {
		t.Error("GetPrivateKey returned unexpected value")
	}

	pub, err := dbManager.GetPublicKey(testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, testIdentity.PublicKey) {
		t.Error("GetPublicKey returned unexpected value")
	}

	uid, err := dbManager.GetUuidForPublicKey(testIdentity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uid[:], testIdentity.Uid[:]) {
		t.Error("GetUuidForPublicKey returned unexpected value")
	}
}

func initDB() (*DatabaseManager, error) {
	conf := &Config{}
	err := conf.Load("", "config.json")
	if err != nil {
		return nil, fmt.Errorf("ERROR: unable to load configuration: %s", err)
	}

	return NewSqlDatabaseInfo(conf.PostgresDSN, TestTableName)
}

func generateRandomIdentity() *Identity {
	priv := make([]byte, 32)
	rand.Read(priv)

	pub := make([]byte, 64)
	rand.Read(pub)

	auth := make([]byte, 16)
	rand.Read(auth)

	return &Identity{
		Uid:        uuid.New(),
		PrivateKey: priv,
		PublicKey:  pub,
		AuthToken:  base64.StdEncoding.EncodeToString(auth),
	}
}

func cleanUp(t *testing.T, dbManager *DatabaseManager) {
	dropTableQuery := fmt.Sprintf("DROP TABLE %s;", TestTableName)
	_, err := dbManager.db.Exec(dropTableQuery)
	if err != nil {
		t.Error(err)
	}
}
