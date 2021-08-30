package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"math/rand"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	testTableName = "test_cose_identity"
	testLoad      = 100
)

func TestDatabaseManager(t *testing.T) {
	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUpDB(t, dm)

	// check DB is ready
	err = dm.IsReady()
	if err != nil {
		t.Error(err)
	}

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

	err = dm.CommitTransaction(tx)
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

func TestNewSqlDatabaseInfo_NotReady(t *testing.T) {
	// use DSN that is valid, but not reachable
	unreachableDSN := "postgres://nousr:nopwd@localhost:0000/nodatabase"

	// we expect no error here
	_, err := NewSqlDatabaseInfo(unreachableDSN, testTableName, &DatabaseParams{})

	require.Error(t, err)
	//defer dm.Close()

	//err = dm.IsReady()
	//if err == nil {
	//	t.Error("IsReady() returned no error for unreachable database")
	//}
}

func TestNewSqlDatabaseInfo_InvalidDSN(t *testing.T) {
	c, err := getDatabaseConfig()
	if err != nil {
		t.Fatal(err)
	}

	// use invalid DSN
	c.PostgresDSN = "this is not a DSN"

	_, err = NewSqlDatabaseInfo(c.PostgresDSN, testTableName, c.dbParams)
	if err == nil {
		t.Fatal("no error returned for invalid DSN")
	}
}

func TestDatabaseManager_IsReady(t *testing.T) {
	c, err := getDatabaseConfig()
	if err != nil {
		t.Fatal(err)
	}

	pg, err := sql.Open(PostgreSql, c.PostgresDSN)
	if err != nil {
		t.Fatal(err)
	}

	dm := &DatabaseManager{
		options: &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
			ReadOnly:  false,
		},
		db:        pg,
		tableName: testTableName,
	}
	defer cleanUpDB(t, dm)

	// table does not exist yet
	tableDoesNotExistError := fmt.Sprintf("relation \"%s\" does not exist", dm.tableName)

	_, err = dm.GetIdentity(uuid.New())
	if !strings.Contains(err.Error(), tableDoesNotExistError) {
		t.Fatalf("unexpected error: %v, expected: %v", err, tableDoesNotExistError)
	}

	err = dm.IsReady()
	if err != nil {
		t.Fatal(err)
	}

	_, err = dm.GetIdentity(uuid.New())
	if err != ErrNotExist {
		t.Error("GetIdentity did not return ErrNotExist")
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

	err = dm.CommitTransaction(tx)
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

func TestDatabaseManager_CancelTransaction(t *testing.T) {
	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUpDB(t, dm)

	// store identity, but cancel context, so transaction will be rolled back
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := dm.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	testIdentity := generateRandomIdentity()

	err = dm.StoreNewIdentity(tx, *testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	// check not exists
	_, err = dm.GetIdentity(testIdentity.Uid)
	if err != ErrNotExist {
		t.Error("GetIdentity did not return ErrNotExist")
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
	dbParams    *DatabaseParams
}

func getDatabaseConfig() (*dbConfig, error) {
	configFileName := "config.json"
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

	c.dbParams = &DatabaseParams{
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

	dm, err := NewSqlDatabaseInfo(c.PostgresDSN, testTableName, c.dbParams)
	if err != nil {
		return nil, err
	}

	_, err = dm.db.Exec(CreateTable(PostgresIdentity, dm.tableName))
	if err != nil {
		return nil, err
	}

	return dm, nil
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
		Uid:          uuid.New(),
		PublicKeyPEM: []byte(base64.StdEncoding.EncodeToString(pub)),
		Auth:         base64.StdEncoding.EncodeToString(auth),
	}
}

func storeIdentity(storageMngr StorageManager, id *Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := storageMngr.StartTransaction(ctx)
	if err != nil {
		return fmt.Errorf("StartTransaction: %v", err)
	}

	err = storageMngr.StoreNewIdentity(tx, *id)
	if err != nil {
		return fmt.Errorf("StoreNewIdentity: %v", err)
	}

	err = storageMngr.CommitTransaction(tx)
	if err != nil {
		return fmt.Errorf("CommitTransaction: %v", err)
	}

	return nil
}

func checkIdentity(storageMngr StorageManager, id *Identity, wg *sync.WaitGroup) error {
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
