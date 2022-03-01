package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
)

var (
	testUuid = uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")
	testPub  = []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEndya+lAutc1ShF7GBj0KPqBoIOj0\nD4GPYgErlfanpplIhXTqLzg8CHKQCy5bwXXi+9HtTpX/4g5TqpydoHkVhg==\n-----END PUBLIC KEY-----\n")
	testAuth = "password1234!"

	testError = errors.New("test error")
)

func TestProtocol(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	testIdentity := Identity{
		Uid:          testUuid,
		PublicKeyPEM: testPub,
		Auth:         testAuth,
	}

	// check not exists
	_, err = p.LoadIdentity(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	exists, err := p.IsInitialized(testIdentity.Uid)
	require.NoError(t, err)
	assert.False(t, exists)

	_, err = p.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
	assert.Equal(t, ErrNotExist, err)

	// store identity
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// check exists
	exists, err = p.IsInitialized(testIdentity.Uid)
	require.NoError(t, err)
	assert.True(t, exists)

	storedIdentity, err := p.LoadIdentity(testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.Uid, storedIdentity.Uid)
	assert.Equal(t, testIdentity.PublicKeyPEM, storedIdentity.PublicKeyPEM)

	storedUid, err := p.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.Uid, storedUid)

	ok, found, err := p.CheckAuth(ctx, testIdentity.Uid, testIdentity.Auth)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, ok)
}

func Test_StoreNewIdentity_BadUUID(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	i := Identity{
		Uid:          uuid.UUID{},
		PublicKeyPEM: testPub,
		Auth:         testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	i := Identity{
		Uid:          testUuid,
		PublicKeyPEM: nil,
		Auth:         testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadPublicKey(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	i := Identity{
		Uid:          testUuid,
		PublicKeyPEM: make([]byte, len(testPub)),
		Auth:         testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilAuth(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	i := Identity{
		Uid:          testUuid,
		PublicKeyPEM: testPub,
		Auth:         "",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func TestProtocol_GetUuidForPublicKey_BadPublicKey(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	_, err = p.GetUuidForPublicKey(make([]byte, 64))
	assert.Error(t, err)
}

func TestExtendedProtocol_CheckAuth(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	i := Identity{
		Uid:          testUuid,
		PublicKeyPEM: testPub,
		Auth:         testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(ctx, i.Uid, i.Auth)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, ok)
}

func TestExtendedProtocol_CheckAuth_Invalid(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	i := Identity{
		Uid:          testUuid,
		PublicKeyPEM: testPub,
		Auth:         testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(ctx, i.Uid, "invalid auth")
	require.NoError(t, err)
	assert.True(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_Invalid_Cached(t *testing.T) {
	storageMngr := &mockStorageMngr{}
	cryptoCtx := &ubirch.ECDSACryptoContext{Keystore: &MockKeystorer{}}

	p, err := NewProtocol(storageMngr, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	i := Identity{
		Uid:          testUuid,
		PublicKeyPEM: testPub,
		Auth:         testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	p.authCache.Store(i.Uid, storageMngr.id.Auth)

	ok, found, err := p.CheckAuth(ctx, i.Uid, "invalid auth")
	require.NoError(t, err)
	assert.True(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_NotFound(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(context.Background(), uuid.New(), "auth")
	require.NoError(t, err)
	assert.False(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_Update(t *testing.T) {
	storageMngr := &mockStorageMngr{}
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(storageMngr, cryptoCtx, &config.Config{KdMaxTotalMemMiB: pw.DefaultMemory, KdUpdateParams: true})
	require.NoError(t, err)

	i := Identity{
		Uid:          testUuid,
		PublicKeyPEM: testPub,
		Auth:         testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	pwHashPreUpdate := storageMngr.id.Auth
	p.pwHasher.Params = pw.GetArgon2idParams(pw.DefaultMemory, pw.DefaultTime,
		2*pw.DefaultParallelism, pw.DefaultKeyLen, pw.DefaultSaltLen)

	ok, found, err := p.CheckAuth(ctx, i.Uid, i.Auth)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, ok)

	assert.NotEqual(t, pwHashPreUpdate, storageMngr.id.Auth)

	ok, found, err = p.CheckAuth(ctx, i.Uid, i.Auth)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, ok)
}

func TestExtendedProtocol_CheckAuth_AuthCache(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	i := Identity{
		Uid:          testUuid,
		PublicKeyPEM: testPub,
		Auth:         testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(ctx, i.Uid, i.Auth)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, ok)

	cachedAuth, found := p.authCache.Load(i.Uid)
	require.True(t, found)
	assert.Equal(t, i.Auth, cachedAuth.(string))
}

func TestProtocol_Cache(t *testing.T) {
	wg := &sync.WaitGroup{}

	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(&mockStorageMngr{}, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	testIdentity := Identity{
		Uid:          testUuid,
		PublicKeyPEM: testPub,
		Auth:         testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// repeatedly check same identity to test cache
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			err := checkIdentity(p, testIdentity, protocolCheckAuth)
			if err != nil {
				t.Errorf("%s: %v", testIdentity.Uid, err)
			}
		}()
	}
	wg.Wait()
}

func TestProtocolLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB()
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p, err := NewProtocol(dm, cryptoCtx, &config.Config{})
	require.NoError(t, err)

	// generate identities
	var testIdentities []Identity
	for i := 0; i < testLoad/10; i++ {
		testId := generateRandomIdentity()

		err = p.Crypto.GenerateKey(testId.Uid)
		require.NoError(t, err)

		testId.PublicKeyPEM, err = p.Crypto.GetPublicKeyPEM(testId.Uid)
		require.NoError(t, err)

		testIdentities = append(testIdentities, testId)
	}

	// store identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(i Identity) {
			defer wg.Done()

			err := storeIdentity(p, i)
			if err != nil {
				t.Errorf("%s: %v", i.Uid, err)
			}
		}(testId)
	}
	wg.Wait()

	// check identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(i Identity) {
			defer wg.Done()

			err := checkIdentity(p, i, protocolCheckAuth)
			if err != nil {
				t.Errorf("%s: %v", i.Uid, err)
			}
		}(testId)
	}
	wg.Wait()
}

func protocolCheckAuth(auth, authToCheck string) error {
	pwHasher := &pw.Argon2idKeyDerivator{}

	_, ok, err := pwHasher.CheckPassword(context.Background(), auth, authToCheck)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("protocolCheckAuth failed: %s != %s", auth, authToCheck)
	}
	return nil
}

type mockStorageMngr struct {
	id Identity
}

var _ StorageManager = (*mockStorageMngr)(nil)

func (m *mockStorageMngr) StartTransaction(context.Context) (TransactionCtx, error) {
	return &mockTx{
		idBuf: Identity{},
		id:    &m.id,
	}, nil
}

func (m *mockStorageMngr) StoreIdentity(t TransactionCtx, i Identity) error {
	tx, ok := t.(*mockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *mockTx")
	}
	tx.idBuf = i

	return nil
}

func (m *mockStorageMngr) LoadIdentity(u uuid.UUID) (*Identity, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return nil, ErrNotExist
	}
	id := m.id
	return &id, nil
}

func (m *mockStorageMngr) GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error) {
	if m.id.PublicKeyPEM == nil || !bytes.Equal(m.id.PublicKeyPEM, pubKey) {
		return uuid.Nil, ErrNotExist
	}
	return m.id.Uid, nil
}

func (m *mockStorageMngr) StoreAuth(t TransactionCtx, u uuid.UUID, a string) error {
	tx, ok := t.(*mockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *mockTx")
	}

	if tx.idBuf.Uid == uuid.Nil || tx.idBuf.Uid != u {
		return fmt.Errorf("tx invalid")
	}

	tx.idBuf.Auth = a
	return nil
}

func (m *mockStorageMngr) LoadAuthForUpdate(t TransactionCtx, u uuid.UUID) (string, error) {
	tx, ok := t.(*mockTx)
	if !ok {
		return "", fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *mockTx")
	}

	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return "", ErrNotExist
	}

	tx.idBuf = m.id

	return m.id.Auth, nil
}

func (m *mockStorageMngr) IsReady() error {
	return nil
}

func (m *mockStorageMngr) Close() {}

type mockTx struct {
	idBuf Identity
	id    *Identity
}

var _ TransactionCtx = (*mockTx)(nil)

func (m *mockTx) Commit() error {
	*m.id = m.idBuf
	*m = mockTx{}
	return nil
}

func (m *mockTx) Rollback() error {
	*m = mockTx{}
	return nil
}

type MockKeystorer struct {
	priv []byte
	pub  []byte
}

var _ ubirch.Keystorer = (*MockKeystorer)(nil)

func (m *MockKeystorer) GetIDs() ([]uuid.UUID, error) {
	panic("implement me")
}

func (m *MockKeystorer) PrivateKeyExists(id uuid.UUID) (bool, error) {
	if len(m.priv) == 0 {
		return false, nil
	}
	return true, nil
}

func (m *MockKeystorer) GetPrivateKey(id uuid.UUID) ([]byte, error) {
	if len(m.priv) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	return m.priv, nil
}

func (m *MockKeystorer) SetPrivateKey(id uuid.UUID, key []byte) error {
	m.priv = key
	return nil
}

func (m *MockKeystorer) PublicKeyExists(id uuid.UUID) (bool, error) {
	if len(m.pub) == 0 {
		return false, nil
	}
	return true, nil
}

func (m *MockKeystorer) GetPublicKey(id uuid.UUID) ([]byte, error) {
	if len(m.pub) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	return m.pub, nil
}

func (m *MockKeystorer) SetPublicKey(id uuid.UUID, key []byte) error {
	m.pub = key
	return nil
}
