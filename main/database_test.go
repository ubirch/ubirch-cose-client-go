package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
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
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	// check not exists
	_, err = dm.GetIdentity(testIdentity.Uid)
	if err != ErrNotExist {
		t.Error("GetIdentity did not return ErrNotExist")
	}

	_, err = dm.GetUuidForPublicKey(testIdentity.PublicKey)
	if err != ErrNotExist {
		t.Error("GetUuidForPublicKey did not return ErrNotExist")
	}

	// store identity
	err = dm.StoreNewIdentity(*testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	// check exists
	idFromDb, err := dm.GetIdentity(testIdentity.Uid)
	if err != nil {
		t.Error(err)
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

	uid, err := dm.GetUuidForPublicKey(testIdentity.PublicKey)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(uid[:], testIdentity.Uid[:]) {
		t.Error("GetUuidForPublicKey returned unexpected value")
	}
}

func TestStoreExisting(t *testing.T) {
	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	// store identity
	err = dm.StoreNewIdentity(*testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	// store same identity again
	err = dm.StoreNewIdentity(*testIdentity)
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
	defer cleanUpDB(t, dm)

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

func cleanUpDB(t *testing.T, dm *DatabaseManager) {
	dropTableQuery := fmt.Sprintf("DROP TABLE %s;", testTableName)
	_, err := dm.db.Exec(dropTableQuery)
	if err != nil {
		t.Error(err)
	}

	dm.Close()
}

func generateRandomIdentity() *Identity {
	pub := make([]byte, 64)
	rand.Read(pub)

	auth := make([]byte, 16)
	rand.Read(auth)

	return &Identity{
		Uid:       uuid.New(),
		PublicKey: pub,
		AuthToken: base64.StdEncoding.EncodeToString(auth),
	}
}

func storeIdentity(ctxMngr ContextManager, id *Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	return ctxMngr.StoreNewIdentity(*id)
}

func checkIdentity(ctxMngr ContextManager, id *Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	idFromCtx, err := ctxMngr.GetIdentity(id.Uid)
	if err != nil {
		return err
	}
	if !bytes.Equal(idFromCtx.PublicKey, id.PublicKey) {
		return fmt.Errorf("GetIdentity returned unexpected PublicKey value")
	}
	if idFromCtx.AuthToken != id.AuthToken {
		return fmt.Errorf("GetIdentity returned unexpected AuthToken value")
	}
	if !bytes.Equal(idFromCtx.Uid[:], id.Uid[:]) {
		return fmt.Errorf("GetIdentity returned unexpected Uid value")
	}

	uid, err := ctxMngr.GetUuidForPublicKey(id.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(uid[:], id.Uid[:]) {
		return fmt.Errorf("GetUuidForPublicKey returned unexpected value: %s, expected: %s", uid, id.Uid)
	}

	return nil
}
