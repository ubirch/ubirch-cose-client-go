package main

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/encrypters"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"math/rand"
	"sync"
	"testing"
)

func TestProtocol(t *testing.T) {
	crypto := &ubirch.ECDSACryptoContext{}

	secret := make([]byte, 32)
	rand.Read(secret)

	enc, err := encrypters.NewKeyEncrypter(secret, crypto)
	if err != nil {
		t.Fatal(err)
	}

	p := &Protocol{
		Crypto:       crypto,
		ctxManager:   &mockCtxMngr{},
		keyEncrypter: enc,

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
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
		Uid:        testUuid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		AuthToken:  testAuth,
	}

	// check not exists
	_, err = p.GetIdentity(testIdentity.Uid)
	if err != ErrNotExist {
		t.Error("GetIdentity did not return ErrNotExist")
	}

	exists, err := p.Exists(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if exists {
		t.Error("Exists returned TRUE")
	}

	err = p.StoreNewIdentity(nil, testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	// check exists
	exists, err = p.Exists(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if !exists {
		t.Error("Exists returned FALSE")
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
}

func TestProtocolLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUp(t, dm)

	crypto := &ubirch.ECDSACryptoContext{}

	secret := make([]byte, 32)
	rand.Read(secret)

	enc, err := encrypters.NewKeyEncrypter(secret, crypto)
	if err != nil {
		t.Fatal(err)
	}

	p := &Protocol{
		Crypto:       crypto,
		ctxManager:   dm,
		keyEncrypter: enc,

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
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

type mockCtxMngr struct {
	id Identity
}

var _ ContextManager = (*mockCtxMngr)(nil)

func (m *mockCtxMngr) StoreNewIdentity(tx interface{}, id Identity) error {
	m.id = id
	return nil
}

func (m *mockCtxMngr) GetIdentity(uid uuid.UUID) (*Identity, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != uid {
		return nil, ErrNotExist
	}
	return &m.id, nil
}

func (m *mockCtxMngr) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	return nil, nil
}

func (m *mockCtxMngr) CloseTransaction(transactionCtx interface{}, commit bool) error {
	return nil
}

func (m *mockCtxMngr) ExistsPrivateKey(uid uuid.UUID) (bool, error) {
	panic("implement me")
}

func (m *mockCtxMngr) GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error) {
	panic("implement me")
}

func (m *mockCtxMngr) Close() {
	panic("implement me")
}
