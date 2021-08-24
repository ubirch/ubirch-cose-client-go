package repository

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"github.com/ubirch/ubirch-cose-client-go/main/ent"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	testTableName = "cose_identity_hsm"
	testLoad      = 100
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

	_, err = dm.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
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
		t.Fatal(err)
	}
	if !bytes.Equal(idFromDb.Uid[:], testIdentity.Uid[:]) {
		t.Error("GetIdentity returned unexpected Uid value")
	}
	if !bytes.Equal(idFromDb.PublicKeyPEM, testIdentity.PublicKeyPEM) {
		t.Error("GetIdentity returned unexpected PublicKeyPEM value")
	}
	if idFromDb.Auth != testIdentity.Auth {
		t.Error("GetIdentity returned unexpected Auth value")
	}

	uid, err := dm.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
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
	var testIdentities []*ent.Identity
	for i := 0; i < testLoad; i++ {
		testIdentities = append(testIdentities, generateRandomIdentity())
	}

	// store identities
	for i, testId := range testIdentities {
		wg.Add(1)
		go func(idx int, identity *ent.Identity) {
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
		go func(id *ent.Identity) {
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
	dbParams    *config.DatabaseParams
}

func getDatabaseConfig() (*dbConfig, error) {
	configFileName := "../config/config.json"
	fileHandle, err := os.Open(configFileName)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%v \n"+
			"--------------------------------------------------------------------------------\n"+
			"Please provide a configuration file \"%s\" which contains a DSN for\n"+
			"a postgres database in order to test the database connection.\n"+
			"{\n\t\"postgresDSN\": \"postgres://<username>:<password>@<hostname>:5432/<database>\"\n}\n"+
			"--------------------------------------------------------------------------------",
			err, configFileName)
	}
	if err != nil {
		return nil, err
	}

	c := &dbConfig{}
	err = json.NewDecoder(fileHandle).Decode(c)
	if err != nil {
		if fileCloseErr := fileHandle.Close(); fileCloseErr != nil {
			fmt.Print(fileCloseErr)
		}
		return nil, err
	}

	err = fileHandle.Close()
	if err != nil {
		return nil, err
	}

	c.dbParams = &config.DatabaseParams{
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 2 * time.Minute,
		ConnMaxIdleTime: 1 * time.Minute,
	}

	return c, nil
}

func initDB() (*DatabaseManager, error) {
	c, err := getDatabaseConfig()
	if err != nil {
		return nil, err
	}

	return NewSqlDatabaseInfo(c.PostgresDSN, testTableName, c.dbParams)
}

func cleanUpDB(t *testing.T, dm *DatabaseManager) {
	dropTableQuery := fmt.Sprintf("DELETE FROM %s;", testTableName)
	_, err := dm.db.Exec(dropTableQuery)
	if err != nil {
		t.Error(err)
	}

	dm.Close()
}

func generateRandomIdentity() *ent.Identity {
	pub := make([]byte, 64)
	rand.Read(pub)

	auth := make([]byte, 32)
	rand.Read(auth)

	return &ent.Identity{
		Uid:          uuid.New(),
		PublicKeyPEM: []byte(base64.StdEncoding.EncodeToString(pub)),
		Auth:         base64.StdEncoding.EncodeToString(auth),
	}
}

func storeIdentity(storageMngr StorageManager, id *ent.Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	return storageMngr.StoreNewIdentity(*id)
}

func checkIdentity(storageMngr StorageManager, id *ent.Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	idFromCtx, err := storageMngr.GetIdentity(id.Uid)
	if err != nil {
		return err
	}
	if !bytes.Equal(idFromCtx.Uid[:], id.Uid[:]) {
		return fmt.Errorf("GetIdentity returned unexpected Uid value")
	}
	if !bytes.Equal(idFromCtx.PublicKeyPEM, id.PublicKeyPEM) {
		return fmt.Errorf("GetIdentity returned unexpected PublicKeyPEM value")
	}
	if idFromCtx.Auth != id.Auth {
		return fmt.Errorf("GetIdentity returned unexpected Auth value")
	}

	uid, err := storageMngr.GetUuidForPublicKey(id.PublicKeyPEM)
	if err != nil {
		return err
	}
	if !bytes.Equal(uid[:], id.Uid[:]) {
		return fmt.Errorf("GetUuidForPublicKey returned unexpected value: %s, expected: %s", uid, id.Uid)
	}

	return nil
}