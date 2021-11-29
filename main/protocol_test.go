package main

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestProtocol(t *testing.T) {
	p := NewProtocol(&mockStorageMngr{}, &Config{})

	testIdentity := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
	}

	// check not exists
	_, err := p.LoadIdentity(testIdentity.Uid)
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
	p := NewProtocol(&mockStorageMngr{}, &Config{})

	i := Identity{
		Uid:          uuid.UUID{},
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	p := NewProtocol(&mockStorageMngr{}, &Config{})

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: nil,
		Auth:         test.Auth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilAuth(t *testing.T) {
	p := NewProtocol(&mockStorageMngr{}, &Config{})

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
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
	p := NewProtocol(&mockStorageMngr{}, &Config{})

	_, err := p.GetUuidForPublicKey(make([]byte, 64))
	assert.Error(t, err)
}

func TestExtendedProtocol_CheckAuth(t *testing.T) {
	p := NewProtocol(&mockStorageMngr{}, &Config{})

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
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
	p := NewProtocol(&mockStorageMngr{}, &Config{})

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
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
	p := NewProtocol(storageMngr, &Config{})

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
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
	p := NewProtocol(&mockStorageMngr{}, &Config{})

	ok, found, err := p.CheckAuth(context.Background(), uuid.New(), "auth")
	require.NoError(t, err)
	assert.False(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_Update(t *testing.T) {
	storageMngr := &mockStorageMngr{}
	p := NewProtocol(storageMngr, &Config{KdMaxTotalMemMiB: pw.DefaultMemory, KdUpdateParams: true})

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
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
	p := NewProtocol(&mockStorageMngr{}, &Config{})

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
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

	p := NewProtocol(&mockStorageMngr{}, &Config{})

	testIdentity := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
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

	p := NewProtocol(dm, &Config{})

	// generate identities
	var testIdentities []Identity
	for i := 0; i < testLoad/10; i++ {
		testId := generateRandomIdentity()

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
