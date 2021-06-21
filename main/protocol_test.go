package main

import (
	"bytes"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
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

	err := p.GenerateKey(uid)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyBytes, err := p.GetPublicKey(uid)
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
		AuthToken:    "password1234",
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

type mockCtxMngr struct {
	id Identity
}

var _ ContextManager = (*mockCtxMngr)(nil)

func (m *mockCtxMngr) StoreNewIdentity(id Identity) error {
	m.id = id
	return nil
}

func (m *mockCtxMngr) GetIdentity(uid uuid.UUID) (*Identity, error) {
	if m.id.Uid == uuid.Nil {
		return nil, ErrNotExist
	}
	return &m.id, nil
}

func (m *mockCtxMngr) GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error) {
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

func (m *mockKeystorer) GetPrivateKey(id uuid.UUID) ([]byte, error) {
	return m.priv, nil
}

func (m *mockKeystorer) SetPrivateKey(id uuid.UUID, key []byte) error {
	m.priv = key
	return nil
}

func (m *mockKeystorer) GetPublicKey(id uuid.UUID) ([]byte, error) {
	return m.pub, nil
}

func (m *mockKeystorer) SetPublicKey(id uuid.UUID, key []byte) error {
	m.pub = key
	return nil
}
