package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

const (
	TestTableName = "test_cose_identity"
	TestUUID      = "2336c75d-a14a-47dd-80d9-3cbe9d560433"
	TestAuthToken = "TEST_auth"
	TestPrivKey   = "Qkp+ZVAlEKCQNvI+OCbY7LKcQVW5iKfFMfzedTI3uG0="
	TestPubKey    = "bvXP3mQ42hXpcqo0ms7Lr1n6Q4L5CsS8HXk0mdXlsXLwYjd35jLlX3iHrXMgUH92N8ujbZ3h3TnLk8a0GikUbg=="
)

var (
	testIdentity = initTestIdentity()
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
}

func initDB() (*DatabaseManager, error) {
	conf := &Config{}
	err := conf.Load("", "config.json")
	if err != nil {
		return nil, fmt.Errorf("ERROR: unable to load configuration: %s", err)
	}

	return NewSqlDatabaseInfo(conf.PostgresDSN, TestTableName)
}

func initTestIdentity() *Identity {
	priv, _ := base64.StdEncoding.DecodeString(TestPrivKey)
	pub, _ := base64.StdEncoding.DecodeString(TestPubKey)

	return &Identity{
		Uid:        uuid.MustParse(TestUUID),
		PrivateKey: priv,
		PublicKey:  pub,
		AuthToken:  TestAuthToken,
	}
}

func cleanUp(t *testing.T, dbManager *DatabaseManager) {
	deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE uid = $1;", TestTableName)
	_, err := dbManager.db.Exec(deleteQuery, TestUUID)
	if err != nil {
		t.Error(err)
	}

	dropTableQuery := fmt.Sprintf("DROP TABLE %s;", TestTableName)
	_, err = dbManager.db.Exec(dropTableQuery)
	if err != nil {
		t.Error(err)
	}
}
