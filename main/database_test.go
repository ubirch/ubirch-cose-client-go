package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
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
	if !bytes.Equal(idFromDb.PW.Hash, testIdentity.PW.Hash) {
		t.Error("GetIdentity returned unexpected PW.DerivedKey value")
	}
	if !bytes.Equal(idFromDb.PW.Salt, testIdentity.PW.Salt) {
		t.Error("GetIdentity returned unexpected PW.Salt value")
	}

	paramsFromDb := &MockPasswordHashingParams{}
	err = paramsFromDb.Decode(idFromDb.PW.Params)
	if err != nil {
		t.Fatalf("failed to decode idFromDb.PW.Params: %v", err)
	}

	testParams := &MockPasswordHashingParams{}
	err = testParams.Decode(testIdentity.PW.Params)
	if err != nil {
		t.Fatalf("failed to decode testIdentity.PW.Params: %v", err)
	}

	if paramsFromDb.aParam != testParams.aParam {
		t.Errorf("GetIdentity returned unexpected PW.Params value")
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
	defer fileHandle.Close()

	c := &dbConfig{}
	err = json.NewDecoder(fileHandle).Decode(c)
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

	return NewSqlDatabaseInfo(c.PostgresDSN, testTableName, c.dbParams)
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

	salt := make([]byte, 16)
	rand.Read(salt)

	p := &MockPasswordHashingParams{
		aParam: rand.Uint32(),
	}

	params, err := p.Encode()
	if err != nil {
		log.Errorf("failed to decode parameter: %v", err)
	}

	return &Identity{
		Uid:          uuid.New(),
		PublicKeyPEM: []byte(base64.StdEncoding.EncodeToString(pub)),
		PW: pw.Password{
			AlgoID: "test-algoID",
			Hash:   auth,
			Salt:   salt,
			Params: params,
		},
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
	if !bytes.Equal(idFromCtx.Uid[:], id.Uid[:]) {
		return fmt.Errorf("GetIdentity returned unexpected Uid value")
	}
	if !bytes.Equal(idFromCtx.PublicKeyPEM, id.PublicKeyPEM) {
		return fmt.Errorf("GetIdentity returned unexpected PublicKeyPEM value")
	}
	if !bytes.Equal(idFromCtx.PW.Hash, id.PW.Hash) {
		return fmt.Errorf("GetIdentity returned unexpected PW.DerivedKey value")
	}
	if !bytes.Equal(idFromCtx.PW.Salt, id.PW.Salt) {
		return fmt.Errorf("GetIdentity returned unexpected PW.Salt value")
	}

	uid, err := ctxMngr.GetUuidForPublicKey(id.PublicKeyPEM)
	if err != nil {
		return err
	}
	if !bytes.Equal(uid[:], id.Uid[:]) {
		return fmt.Errorf("GetUuidForPublicKey returned unexpected value: %s, expected: %s", uid, id.Uid)
	}

	return nil
}

type MockPasswordHashingParams struct {
	aParam       uint32
	anotherParam []byte
}

func (p *MockPasswordHashingParams) Decode(params map[string]interface{}) error {
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return err
	}

	return json.Unmarshal(paramBytes, p)
}

func (p *MockPasswordHashingParams) Encode() (params map[string]interface{}, err error) {
	paramBytes, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(paramBytes, &params)
	if err != nil {
		return nil, err
	}

	return params, nil
}
