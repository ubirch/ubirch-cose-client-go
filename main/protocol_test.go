package main

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestProtocol(t *testing.T) {
	testUid := uuid.New()

	p := &Protocol{
		Crypto: &ubirch.ECDSACryptoContext{
			Keystore: &mockKeystorer{},
		},
		ctxManager: &mockCtxMngr{},

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
	}
	defer p.Close()

	err := p.GenerateKey(testUid)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyBytes, err := p.GetPublicKey(testUid)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := p.PublicKeyBytesToPEM(pubKeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	testIdentity := Identity{
		Uid:          testUid,
		PublicKeyPEM: pubKeyPEM,
		AuthToken:    test.Auth,
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

	_, err = p.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
	if err != ErrNotExist {
		t.Error("GetUuidForPublicKey did not return ErrNotExist")
	}

	err = p.StoreNewIdentity(testIdentity)
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

	if !bytes.Equal(storedIdentity.PublicKeyPEM, testIdentity.PublicKeyPEM) {
		t.Error("GetIdentity returned unexpected PublicKeyPEM value")
	}
	if storedIdentity.AuthToken != testIdentity.AuthToken {
		t.Error("GetIdentity returned unexpected AuthToken value")
	}
	if !bytes.Equal(storedIdentity.Uid[:], testIdentity.Uid[:]) {
		t.Error("GetIdentity returned unexpected Uid value")
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
		ctxManager: dm,

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
	}
	defer p.Close()

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
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &mockKeystorer{},
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})
	defer p.Close()

	i := Identity{
		Uid:          uuid.UUID{},
		PublicKeyPEM: test.PubKey,
		AuthToken:    test.Auth,
	}

	err := p.StoreNewIdentity(i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid UUID")
	}
}

// todo
//func Test_StoreNewIdentity_BadPublicKey(t *testing.T) {
//	cryptoCtx := &ubirch.ECDSACryptoContext{
//		Keystore: &mockKeystorer{},
//	}
//
//	p := NewProtocol(cryptoCtx, &mockCtxMngr{})
//	defer p.Close()
//
//	i := Identity{
//		Uid:          test.Uuid,
//		PublicKeyPEM: make([]byte, 64),
//		AuthToken:    test.Auth,
//	}
//
//	err := p.StoreNewIdentity(i)
//	if err == nil {
//		t.Error("StoreNewIdentity did not return error for invalid public key")
//	}
//}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &mockKeystorer{},
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})
	defer p.Close()

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: nil,
		AuthToken:    test.Auth,
	}

	err := p.StoreNewIdentity(i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid public key")
	}
}

func Test_StoreNewIdentity_NilAuth(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &mockKeystorer{},
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})
	defer p.Close()

	i := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		AuthToken:    "",
	}

	err := p.StoreNewIdentity(i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid auth token")
	}
}

func TestProtocol_Cache(t *testing.T) {
	wg := &sync.WaitGroup{}

	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &mockKeystorer{},
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})
	defer p.Close()

	testIdentity := Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		AuthToken:    test.Auth,
	}

	err := p.StoreNewIdentity(testIdentity)
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
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &mockKeystorer{},
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})
	defer p.Close()

	_, err := p.GetUuidForPublicKey(make([]byte, 64))
	if err == nil {
		t.Error("GetUuidForPublicKey did not return error for invalid public key")
	}
}

type mockCtxMngr struct {
	id Identity
}

var _ ContextManager = (*mockCtxMngr)(nil)

func (m *mockCtxMngr) StoreNewIdentity(id Identity) error {
	m.id = id
	return nil
}

func (m *mockCtxMngr) GetIdentity(uid uuid.UUID) (Identity, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != uid {
		return Identity{}, ErrNotExist
	}
	return m.id, nil
}

func (m *mockCtxMngr) GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error) {
	if m.id.PublicKeyPEM == nil || !bytes.Equal(m.id.PublicKeyPEM, pubKey) {
		return uuid.Nil, ErrNotExist
	}
	return m.id.Uid, nil
}

func (m *mockCtxMngr) Close() {}

type mockKeystorer struct {
	priv []byte
	pub  []byte
}

var _ ubirch.Keystorer = (*mockKeystorer)(nil)

func (m *mockKeystorer) GetIDs() ([]uuid.UUID, error) {
	panic("implement me")
}

func (m *mockKeystorer) PrivateKeyExists(id uuid.UUID) (bool, error) {
	if len(m.priv) == 0 {
		return false, nil
	}
	return true, nil
}

func (m *mockKeystorer) GetPrivateKey(id uuid.UUID) ([]byte, error) {
	if len(m.priv) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	return m.priv, nil
}

func (m *mockKeystorer) SetPrivateKey(id uuid.UUID, key []byte) error {
	m.priv = key
	return nil
}

func (m *mockKeystorer) PublicKeyExists(id uuid.UUID) (bool, error) {
	if len(m.pub) == 0 {
		return false, nil
	}
	return true, nil
}

func (m *mockKeystorer) GetPublicKey(id uuid.UUID) ([]byte, error) {
	if len(m.pub) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	return m.pub, nil
}

func (m *mockKeystorer) SetPublicKey(id uuid.UUID, key []byte) error {
	m.pub = key
	return nil
}
