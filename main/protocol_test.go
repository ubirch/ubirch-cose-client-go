package main

import (
	"bytes"
	"context"
	"math/rand"
	"sync"
	"testing"

	"github.com/google/uuid"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestProtocol(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPEM, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := p.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	testIdentity := Identity{
		Uid:        test.Uuid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		AuthToken:  test.Auth,
	}

	// check not exists
	_, err = p.GetIdentity(testIdentity.Uid)
	if err != ErrNotExist {
		t.Error("GetIdentity did not return ErrNotExist")
	}

	exists, err := p.isInitialized(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if exists {
		t.Error("isInitialized returned TRUE")
	}

	_, err = p.GetUuidForPublicKey(testIdentity.PublicKey)
	if err != ErrNotExist {
		t.Error("GetUuidForPublicKey did not return ErrNotExist")
	}

	// store identity
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = p.StoreNewIdentity(tx, testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	err = p.CloseTransaction(tx, Commit)
	if err != nil {
		t.Fatal(err)
	}

	// check exists
	exists, err = p.isInitialized(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if !exists {
		t.Error("isInitialized returned FALSE")
	}

	storedIdentity, err := p.GetIdentity(testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(storedIdentity.PrivateKey, testIdentity.PrivateKey) {
		t.Error("GetIdentity returned unexpected PrivateKey value")
	}
	if !bytes.Equal(storedIdentity.PublicKey, testIdentity.PublicKey) {
		t.Error("GetIdentity returned unexpected PublicKey value")
	}
	if storedIdentity.AuthToken != testIdentity.AuthToken {
		t.Error("GetIdentity returned unexpected AuthToken value")
	}
	if !bytes.Equal(storedIdentity.Uid[:], testIdentity.Uid[:]) {
		t.Error("GetIdentity returned unexpected Uid value")
	}

	storedUid, err := p.GetUuidForPublicKey(testIdentity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedUid[:], testIdentity.Uid[:]) {
		t.Errorf("GetUuidForPublicKey returned unexpected value: %s, expected: %s", storedUid[:], testIdentity.Uid[:])
	}
}

func TestProtocolLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUpDB(t, dm)

	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(dm, secret)
	if err != nil {
		t.Fatal(err)
	}

	// generate identities
	var testIdentities []*Identity
	for i := 0; i < testLoad/10; i++ {
		testId := generateRandomIdentity()

		testId.PrivateKey, err = p.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}

		testId.PublicKey, err = p.GetPublicKeyFromPrivateKey(testId.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}

		testIdentities = append(testIdentities, testId)
	}

	// store identities
	for i, testId := range testIdentities {
		wg.Add(1)
		go func(idx int, identity *Identity) {
			err := storeIdentity(p, identity, wg)
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
			err := checkIdentity(p, id, wg)
			if err != nil {
				t.Errorf("%s: %v", id.Uid, err)
			}
		}(testId)
	}
	wg.Wait()
}

func Test_BadNewProtocol(t *testing.T) {
	secret := make([]byte, 31)
	rand.Read(secret)

	_, err := NewProtocol(&mockStorageMngr{}, secret)
	if err == nil {
		t.Error("NewProtocol did not return error for invalid secret")
	}
}

func Test_StoreNewIdentity_BadUUID(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	privKeyPEM, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := p.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	i := Identity{
		Uid:        uuid.UUID{},
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		AuthToken:  test.Auth,
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid UUID")
	}
}

func Test_StoreNewIdentity_BadPrivateKey(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	privKeyPEM, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := p.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	i := Identity{
		Uid:        test.Uuid,
		PrivateKey: make([]byte, 32),
		PublicKey:  pubKeyPEM,
		AuthToken:  test.Auth,
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid private key")
	}
}

func Test_StoreNewIdentity_NilPrivateKey(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	privKeyPEM, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := p.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	i := Identity{
		Uid:        test.Uuid,
		PrivateKey: nil,
		PublicKey:  pubKeyPEM,
		AuthToken:  test.Auth,
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid private key")
	}
}

func Test_StoreNewIdentity_BadPublicKey(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	privKeyPEM, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	i := Identity{
		Uid:        test.Uuid,
		PrivateKey: privKeyPEM,
		PublicKey:  make([]byte, 64),
		AuthToken:  test.Auth,
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid public key")
	}
}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPEM, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	i := Identity{
		Uid:        test.Uuid,
		PrivateKey: privKeyPEM,
		PublicKey:  nil,
		AuthToken:  test.Auth,
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid public key")
	}
}

func Test_StoreNewIdentity_NilAuth(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPEM, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := p.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	i := Identity{
		Uid:        test.Uuid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		AuthToken:  "",
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid auth token")
	}
}

func TestProtocol_Cache(t *testing.T) {
	wg := &sync.WaitGroup{}

	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPEM, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := p.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	testIdentity := Identity{
		Uid:        test.Uuid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		AuthToken:  test.Auth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = p.StoreNewIdentity(tx, testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	err = p.CloseTransaction(tx, Commit)
	if err != nil {
		t.Fatal(err)
	}

	// repeatedly check same identity to test cache
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			err := checkIdentity(p, &testIdentity, wg)
			if err != nil {
				t.Errorf("%s: %v", testIdentity.Uid, err)
			}
		}()
	}
	wg.Wait()
}

func TestProtocol_GetUuidForPublicKey_BadPublicKey(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.GetUuidForPublicKey(make([]byte, 64))
	if err == nil {
		t.Error("GetUuidForPublicKey did not return error for invalid public key")
	}
}

type mockStorageMngr struct {
	id Identity
}

var _ StorageManager = (*mockStorageMngr)(nil)

var idBuf = &Identity{}

func (m *mockStorageMngr) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	return nil, nil
}

func (m *mockStorageMngr) CloseTransaction(transactionCtx interface{}, commit bool) error {
	if commit {
		m.id = *idBuf
	}
	return nil
}

func (m *mockStorageMngr) StoreNewIdentity(transactionCtx interface{}, id Identity) error {
	idBuf = &id
	return nil
}

func (m *mockStorageMngr) GetIdentity(uid uuid.UUID) (Identity, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != uid {
		return Identity{}, ErrNotExist
	}
	return m.id, nil
}

func (m *mockStorageMngr) GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error) {
	if m.id.PublicKey == nil || !bytes.Equal(m.id.PublicKey, pubKey) {
		return uuid.Nil, ErrNotExist
	}
	return m.id.Uid, nil
}

func (m *mockStorageMngr) IsRecoverable(error) bool {
	return false
}

func (m *mockStorageMngr) IsReady() error {
	return nil
}

func (m *mockStorageMngr) Close() {}
