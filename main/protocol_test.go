package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

const (
	PrivHex = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"                                                                 //"10a0bef246575ea219e15bffbb6704d2a58b0e4aa99f101f12f0b1ce7a143559"
	PubHex  = "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771" //"92bbd65d59aecbdf7b497fb4dcbdffa22833613868ddf35b44f5bd672496664a2cc1d228550ae36a1d0210a3b42620b634dc5d22ecde9e12f37d66eeedee3e6a"
)

var (
	testUuid      = uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")
	testKey, _    = hex.DecodeString(PrivHex)
	testPubKey, _ = hex.DecodeString(PubHex)
	testAuth      = "password1234!"
	testSecret, _ = base64.StdEncoding.DecodeString("4qo9HvXPFX3DWJQAa0ljHbGx+hnsyTF0rFmAdDMGjXE=")

	testError = errors.New("test error")
)

func TestProtocol(t *testing.T) {
	p, err := NewProtocol(&mockStorageMngr{}, &config.Config{SecretBytes: testSecret})
	require.NoError(t, err)

	testIdentity := Identity{
		Uid: testUuid,
		//PrivateKey:
		PublicKey: testPubKey,
		Auth:      testAuth,
	}

	// check not exists
	_, err = p.LoadIdentity(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	exists, err := p.IsInitialized(testIdentity.Uid)
	require.NoError(t, err)
	assert.False(t, exists)

	_, err = p.GetUuidForPublicKey(testIdentity.PublicKey)
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
	assert.Equal(t, testIdentity.PublicKey, storedIdentity.PublicKey)

	storedUid, err := p.GetUuidForPublicKey(testIdentity.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.Uid, storedUid)

	ok, found, err := p.CheckAuth(ctx, testIdentity.Uid, testIdentity.Auth)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, ok)
}

func Test_StoreNewIdentity_BadUUID(t *testing.T) {
	p, err := NewProtocol(&mockStorageMngr{}, &config.Config{SecretBytes: testSecret})
	require.NoError(t, err)

	i := Identity{
		Uid:       uuid.UUID{},
		PublicKey: testPubKey,
		Auth:      testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	p, err := NewProtocol(&mockStorageMngr{}, &config.Config{SecretBytes: testSecret})
	require.NoError(t, err)

	i := Identity{
		Uid:       testUuid,
		PublicKey: nil,
		Auth:      testAuth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

// FIXME
//func Test_StoreNewIdentity_BadPublicKey(t *testing.T) {
//	p := NewProtocol(&mockStorageMngr{}, &Config{})
//
//	i := Identity{
//		Uid:          testUuid,
//		PublicKey: make([]byte, len(testPubKey)),
//		Auth:         testAuth,
//	}
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	tx, err := p.StartTransaction(ctx)
//	require.NoError(t, err)
//
//	err = p.StoreIdentity(tx, i)
//	assert.Error(t, err)
//}

func Test_StoreNewIdentity_NilAuth(t *testing.T) {
	p, err := NewProtocol(&mockStorageMngr{}, &config.Config{SecretBytes: testSecret})
	require.NoError(t, err)

	i := Identity{
		Uid:       testUuid,
		PublicKey: testPubKey,
		Auth:      "",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func TestProtocol_GetUuidForPublicKey_BadPublicKey(t *testing.T) {
	p, err := NewProtocol(&mockStorageMngr{}, &config.Config{SecretBytes: testSecret})
	require.NoError(t, err)

	_, err = p.GetUuidForPublicKey(make([]byte, 64))
	assert.Error(t, err)
}

func TestExtendedProtocol_CheckAuth(t *testing.T) {
	p, err := NewProtocol(&mockStorageMngr{}, &config.Config{SecretBytes: testSecret})
	require.NoError(t, err)

	i := Identity{
		Uid:       testUuid,
		PublicKey: testPubKey,
		Auth:      testAuth,
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
	p, err := NewProtocol(&mockStorageMngr{}, &config.Config{SecretBytes: testSecret})
	require.NoError(t, err)

	i := Identity{
		Uid:       testUuid,
		PublicKey: testPubKey,
		Auth:      testAuth,
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
	p, err := NewProtocol(storageMngr, &config.Config{})
	require.NoError(t, err)

	i := Identity{
		Uid:       testUuid,
		PublicKey: testPubKey,
		Auth:      testAuth,
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
	p, err := NewProtocol(&mockStorageMngr{}, &config.Config{SecretBytes: testSecret})
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(context.Background(), uuid.New(), "auth")
	require.NoError(t, err)
	assert.False(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_AuthCache(t *testing.T) {
	p, err := NewProtocol(&mockStorageMngr{}, &config.Config{SecretBytes: testSecret})
	require.NoError(t, err)

	i := Identity{
		Uid:       testUuid,
		PublicKey: testPubKey,
		Auth:      testAuth,
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

	p, err := NewProtocol(&mockStorageMngr{}, &config.Config{SecretBytes: testSecret})
	require.NoError(t, err)

	testIdentity := Identity{
		Uid:       testUuid,
		PublicKey: testPubKey,
		Auth:      testAuth,
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

	p, err := NewProtocol(dm, &config.Config{})
	require.NoError(t, err)

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
	if auth != authToCheck {
		return fmt.Errorf("auth check failed")
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
	if m.id.PublicKey == nil || !bytes.Equal(m.id.PublicKey, pubKey) {
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
