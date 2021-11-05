package main

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestProtocol(t *testing.T) {
	testUid := uuid.New()

	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	err := cryptoCtx.GenerateKey(testUid)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := cryptoCtx.GetPublicKeyPEM(testUid)
	if err != nil {
		t.Fatal(err)
	}

	p := &Protocol{
		StorageManager: &mockStorageMngr{},

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
	}

	testIdentity := Identity{
		Uid:          testUid,
		PublicKeyPEM: pubKeyPEM,
		Auth:         test.Auth,
	}

	// check not exists
	_, err = p.GetIdentity(testIdentity.Uid)
	if err != ErrNotExist {
		t.Error("GetIdentity did not return ErrNotExist")
	}

	exists, err := p.IsInitialized(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if exists {
		t.Error("IsInitialized returned TRUE")
	}

	_, err = p.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
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

	err = p.CommitTransaction(tx)
	if err != nil {
		t.Fatal(err)
	}

	// check exists
	exists, err = p.IsInitialized(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if !exists {
		t.Error("IsInitialized returned FALSE")
	}

	storedIdentity, err := p.GetIdentity(testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(storedIdentity.Uid[:], testIdentity.Uid[:]) {
		t.Error("GetIdentity returned unexpected Uid value")
	}
	if !bytes.Equal(storedIdentity.PublicKeyPEM, testIdentity.PublicKeyPEM) {
		t.Error("GetIdentity returned unexpected PublicKeyPEM value")
	}
	if storedIdentity.Auth != testIdentity.Auth {
		t.Error("GetIdentity returned unexpected Auth value")
	}

	storedUid, err := p.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
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

	p := &Protocol{
		StorageManager: dm,

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
	}

	// generate identities
	var testIdentities []*Identity
	for i := 0; i < testLoad/10; i++ {
		testId := generateRandomIdentity()

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

func Test_StoreNewIdentity_BadUUID(t *testing.T) {
	conf := &Config{
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p := NewProtocol(&mockStorageMngr{}, conf)

	i := Identity{
		Uid:          uuid.UUID{},
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = p.StoreNewIdentity(tx, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid UUID")
	}
}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	conf := &Config{
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p := NewProtocol(&mockStorageMngr{}, conf)

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: nil,
		Auth:         test.Auth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = p.StoreNewIdentity(tx, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid public key")
	}
}

func Test_StoreNewIdentity_NilAuth(t *testing.T) {
	conf := &Config{
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p := NewProtocol(&mockStorageMngr{}, conf)

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         "",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = p.StoreNewIdentity(tx, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid auth token")
	}
}

func TestProtocol_Cache(t *testing.T) {
	wg := &sync.WaitGroup{}

	conf := &Config{
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p := NewProtocol(&mockStorageMngr{}, conf)

	testIdentity := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
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

	err = p.CommitTransaction(tx)
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
	conf := &Config{
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p := NewProtocol(&mockStorageMngr{}, conf)

	_, err := p.GetUuidForPublicKey(make([]byte, 64))
	if err == nil {
		t.Error("GetUuidForPublicKey did not return error for invalid public key")
	}
}

type mockStorageMngr struct {
	id Identity
}

var _ StorageManager = (*mockStorageMngr)(nil)

var idBuf = &Identity{}

func (m *mockStorageMngr) StartTransaction(context.Context) (interface{}, error) {
	return nil, nil
}

func (m *mockStorageMngr) CommitTransaction(interface{}) error {
	m.id = *idBuf
	return nil
}

func (m *mockStorageMngr) StoreNewIdentity(_ interface{}, id Identity) error {
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
	if m.id.PublicKeyPEM == nil || !bytes.Equal(m.id.PublicKeyPEM, pubKey) {
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
