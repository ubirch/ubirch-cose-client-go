package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testTableName = "test_cose_identity"
	testLoad      = 100
)

func TestDatabaseManager(t *testing.T) {
	dm, err := initDB()
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	// check DB is ready
	err = dm.IsReady()
	require.NoError(t, err)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// check not exists
	_, err = dm.LoadIdentity(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	_, err = dm.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
	assert.Equal(t, ErrNotExist, err)

	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)

	_, err = dm.LoadAuthForUpdate(tx, testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	err = tx.Rollback()
	require.NoError(t, err)

	// store identity
	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// check exists
	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	auth, err := dm.LoadAuthForUpdate(tx, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.Auth, auth)

	err = tx.Commit()
	require.NoError(t, err)

	i, err := dm.LoadIdentity(testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.Uid, i.Uid)
	assert.Equal(t, testIdentity.PublicKeyPEM, i.PublicKeyPEM)
	assert.Equal(t, testIdentity.Auth, i.Auth)

	uid, err := dm.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.Uid, uid)
}

func TestDatabaseManager_StoreAuth(t *testing.T) {
	dm, err := initDB()
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	newAuth := make([]byte, 64)
	rand.Read(newAuth)

	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	auth, err := dm.LoadAuthForUpdate(tx, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.Auth, auth)

	err = dm.StoreAuth(tx, testIdentity.Uid, base64.StdEncoding.EncodeToString(newAuth))
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	tx2, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx2)

	auth, err = dm.LoadAuthForUpdate(tx2, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString(newAuth), auth)
}

func TestNewSqlDatabaseInfo_NotReady(t *testing.T) {
	// use DSN that is valid, but not reachable
	unreachableDSN := "postgres://nousr:nopwd@localhost:0000/nodatabase"

	// we expect no error here
	dm, err := NewSqlDatabaseInfo(unreachableDSN, testTableName, &DatabaseParams{})
	require.NoError(t, err)
	defer dm.Close()

	err = dm.IsReady()
	require.Error(t, err)
}

func TestNewSqlDatabaseInfo_InvalidDSN(t *testing.T) {
	c, err := getDatabaseConfig()
	require.NoError(t, err)

	// use invalid DSN
	c.PostgresDSN = "this is not a DSN"

	_, err = NewSqlDatabaseInfo(c.PostgresDSN, testTableName, c.dbParams)
	if err == nil {
		t.Fatal("no error returned for invalid DSN")
	}
}

func TestDatabaseManager_IsReady(t *testing.T) {
	c, err := getDatabaseConfig()
	require.NoError(t, err)

	pg, err := sql.Open(PostgreSql, c.PostgresDSN)
	require.NoError(t, err)

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

	_, err = dm.LoadIdentity(uuid.New())
	if err == nil || !strings.Contains(err.Error(), tableDoesNotExistError) {
		t.Fatalf("unexpected error: %v, expected: %v", err, tableDoesNotExistError)
	}

	err = dm.IsReady()
	require.NoError(t, err)

	_, err = dm.LoadIdentity(uuid.New())
	assert.Equal(t, ErrNotExist, err)
}

func TestStoreExisting(t *testing.T) {
	dm, err := initDB()
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	// store identity
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// store same identity again
	tx2, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx2)

	err = dm.StoreIdentity(tx2, testIdentity)
	assert.Error(t, err)
}

func TestDatabaseManager_CancelTransaction(t *testing.T) {
	dm, err := initDB()
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	// store identity, but cancel context, so transaction will be rolled back
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	cancel()

	// check not exists
	_, err = dm.LoadIdentity(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)
}

func TestDatabaseLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB()
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	// generate identities
	var testIdentities []Identity
	for i := 0; i < testLoad; i++ {
		testIdentities = append(testIdentities, generateRandomIdentity())
	}

	// store identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(i Identity) {
			err := storeIdentity(dm, i, wg)
			if err != nil {
				t.Errorf("%s: identity could not be stored: %v", i.Uid, err)
			}
		}(testId)
	}
	wg.Wait()

	// check identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(i Identity) {
			err := checkIdentity(dm, i, dbCheckAuth, wg)
			if err != nil {
				t.Errorf("%s: %v", i.Uid, err)
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
	assert.NoError(t, err)

	dm.Close()
}

func generateRandomIdentity() Identity {
	pub := make([]byte, 64)
	rand.Read(pub)

	auth := make([]byte, 16)
	rand.Read(auth)

	return Identity{
		Uid:          uuid.New(),
		PublicKeyPEM: []byte(base64.StdEncoding.EncodeToString(pub)),
		Auth:         base64.StdEncoding.EncodeToString(auth),
	}
}

func storeIdentity(storageMngr StorageManager, id Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := storageMngr.StartTransaction(ctx)
	if err != nil {
		return fmt.Errorf("StartTransaction: %v", err)
	}

	err = storageMngr.StoreIdentity(tx, id)
	if err != nil {
		return fmt.Errorf("StoreIdentity: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("Commit: %v", err)
	}

	return nil
}

func dbCheckAuth(auth, authToCheck string) error {
	if auth != authToCheck {
		return fmt.Errorf("auth check failed")
	}

	return nil
}

func checkIdentity(storageMngr StorageManager, id Identity, checkAuth func(string, string) error, wg *sync.WaitGroup) error {
	defer wg.Done()

	idFromCtx, err := storageMngr.LoadIdentity(id.Uid)
	if err != nil {
		return fmt.Errorf("LoadIdentity: %v", err)
	}
	if !bytes.Equal(idFromCtx.Uid[:], id.Uid[:]) {
		return fmt.Errorf("LoadIdentity returned unexpected Uid value")
	}
	if !bytes.Equal(idFromCtx.PublicKeyPEM, id.PublicKeyPEM) {
		return fmt.Errorf("LoadIdentity returned unexpected PublicKeyPEM value")
	}

	err = checkAuth(idFromCtx.Auth, id.Auth)
	if err != nil {
		return fmt.Errorf("checkAuth: %v", err)
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
