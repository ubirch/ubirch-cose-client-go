package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"
)

const (
	testTableName = "test_cose_identity"
	testLoad      = 10000
)

func TestDatabaseManager(t *testing.T) {
	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUp(t, dm)

	testIdentity := generateRandomIdentity()

	// check not exists
	_, err = dm.GetIdentity(testIdentity.Uid)
	if err != ErrNotExist {
		t.Error("GetIdentity did not return ErrNotExist")
	}

	exists, err := dm.ExistsPrivateKey(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if exists {
		t.Error("ExistsPrivateKey returned TRUE")
	}

	_, err = dm.GetPrivateKey(testIdentity.Uid)
	if err != ErrNotExist {
		t.Error("GetPrivateKey did not return ErrNotExist")
	}

	_, err = dm.GetPublicKey(testIdentity.Uid)
	if err != ErrNotExist {
		t.Error("GetPublicKey did not return ErrNotExist")
	}

	_, err = dm.GetAuthToken(testIdentity.Uid)
	if err != ErrNotExist {
		t.Error("GetAuthToken did not return ErrNotExist")
	}

	_, err = dm.GetUuidForPublicKey(testIdentity.PublicKey)
	if err != ErrNotExist {
		t.Error("GetUuidForPublicKey did not return ErrNotExist")
	}

	// store identity
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := dm.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = dm.StoreNewIdentity(tx, *testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	err = dm.CloseTransaction(tx, Commit)
	if err != nil {
		t.Fatal(err)
	}

	// check exists
	exists, err = dm.ExistsPrivateKey(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if !exists {
		t.Error("ExistsPrivateKey returned FALSE")
	}

	// get attributes
	priv, err := dm.GetPrivateKey(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(priv, testIdentity.PrivateKey) {
		t.Error("GetPrivateKey returned unexpected value")
	}

	pub, err := dm.GetPublicKey(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(pub, testIdentity.PublicKey) {
		t.Error("GetPublicKey returned unexpected value")
	}

	auth, err := dm.GetAuthToken(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if auth != testIdentity.AuthToken {
		t.Error("GetAuthToken returned unexpected value")
	}

	uid, err := dm.GetUuidForPublicKey(testIdentity.PublicKey)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(uid[:], testIdentity.Uid[:]) {
		t.Error("GetUuidForPublicKey returned unexpected value")
	}

	idFromDb, err := dm.GetIdentity(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(idFromDb.PrivateKey, testIdentity.PrivateKey) {
		t.Error("GetIdentity returned unexpected PrivateKey value")
	}
	if !bytes.Equal(idFromDb.PublicKey, testIdentity.PublicKey) {
		t.Error("GetIdentity returned unexpected PublicKey value")
	}
	if idFromDb.AuthToken != testIdentity.AuthToken {
		t.Error("GetIdentity returned unexpected AuthToken value")
	}
	if !bytes.Equal(idFromDb.Uid[:], testIdentity.Uid[:]) {
		t.Error("GetIdentity returned unexpected Uid value")
	}
}

func TestStoreExisting(t *testing.T) {
	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUp(t, dm)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := dm.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = dm.StoreNewIdentity(tx, *testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	err = dm.CloseTransaction(tx, Commit)
	if err != nil {
		t.Fatal(err)
	}

	// store same identity again
	tx2, err := dm.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = dm.StoreNewIdentity(tx2, *testIdentity)
	if err == nil {
		t.Fatal("existing identity was overwritten")
	}
}

func TestDatabaseLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUp(t, dm)

	// generate identities
	var testIdentities []*Identity
	for i := 0; i < testLoad; i++ {
		testIdentities = append(testIdentities, generateRandomIdentity())
	}

	// store identities
	for i, testId := range testIdentities {
		wg.Add(1)
		go func(idx int, identity *Identity) {
			err := storeIdentity(dm, identity, wg)
			if err != nil {
				t.Errorf("%s: identity could not be stored: %v", identity.Uid, err)
			}
		}(i, testId)
	}
	wg.Wait()

	// check identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(id *Identity) {
			err := checkIdentity(dm, id, wg)
			if err != nil {
				t.Errorf("%s: %v", id.Uid, err)
			}
		}(testId)
	}
	wg.Wait()

	// FIXME
	//if dm.db.Stats().OpenConnections > dm.db.Stats().Idle {
	//	t.Errorf("%d open connections, %d idle", dm.db.Stats().OpenConnections, dm.db.Stats().Idle)
	//}
}

type dbConfig struct {
	PostgresDSN string
}

func initDB() (*DatabaseManager, error) {
	testDbParams := &DatabaseParams{
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 2 * time.Minute,
		ConnMaxIdleTime: 1 * time.Minute,
	}

	fileHandle, err := os.Open("config.json")
	if err != nil {
		return nil, err
	}
	defer fileHandle.Close()

	c := &dbConfig{}
	err = json.NewDecoder(fileHandle).Decode(c)
	if err != nil {
		return nil, err
	}

	return NewSqlDatabaseInfo(c.PostgresDSN, testTableName, testDbParams)
}

func cleanUp(t *testing.T, dm *DatabaseManager) {
	dropTableQuery := fmt.Sprintf("DROP TABLE %s;", testTableName)
	_, err := dm.db.Exec(dropTableQuery)
	if err != nil {
		t.Error(err)
	}

	err = dm.db.Close()
	if err != nil {
		t.Error(err)
	}
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

func storeIdentity(ctxMngr ContextManager, id *Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := ctxMngr.StartTransaction(ctx)
	if err != nil {
		return fmt.Errorf("StartTransaction: %v", err)
	}

	err = ctxMngr.StoreNewIdentity(tx, *id)
	if err != nil {
		return fmt.Errorf("StoreNewIdentity: %v", err)
	}

	err = ctxMngr.CloseTransaction(tx, Commit)
	if err != nil {
		return fmt.Errorf("CloseTransaction: %v", err)
	}

	return nil
}

func checkIdentity(ctxMngr ContextManager, id *Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	exists, err := ctxMngr.ExistsPrivateKey(id.Uid)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("ExistsPrivateKey returned FALSE")
	}

	uid, err := ctxMngr.GetUuidForPublicKey(id.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(uid[:], id.Uid[:]) {
		return fmt.Errorf("GetUuidForPublicKey returned unexpected value: %s, expected: %s", uid, id.Uid)
	}

	idFromDb, err := ctxMngr.GetIdentity(id.Uid)
	if err != nil {
		return err
	}
	if !bytes.Equal(idFromDb.PrivateKey, id.PrivateKey) {
		return fmt.Errorf("GetIdentity returned unexpected PrivateKey value")
	}
	if !bytes.Equal(idFromDb.PublicKey, id.PublicKey) {
		return fmt.Errorf("GetIdentity returned unexpected PublicKey value")
	}
	if idFromDb.AuthToken != id.AuthToken {
		return fmt.Errorf("GetIdentity returned unexpected AuthToken value")
	}
	if !bytes.Equal(idFromDb.Uid[:], id.Uid[:]) {
		return fmt.Errorf("GetIdentity returned unexpected Uid value")
	}

	return nil
}
