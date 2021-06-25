package main

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"math/rand"
	"sync"
	"testing"
)

func TestProtocol(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockCtxMngr{}, secret)
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

	_, err = p.GetUuidForPublicKey(testIdentity.PublicKey)
	if err != ErrNotExist {
		t.Error("GetUuidForPublicKey did not return ErrNotExist")
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

	uid, err := p.GetUuidForPublicKey(testIdentity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(uid[:], testIdentity.Uid[:]) {
		t.Error("GetUuidForPublicKey returned unexpected Uid value")
	}
}

func TestProtocolLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUp(t, dm)

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

	_, err := NewProtocol(&mockCtxMngr{}, secret)
	if err == nil {
		t.Error("NewProtocol did not return error for invalid secret")
	}
}

func Test_StoreNewIdentity_BadUUID(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockCtxMngr{}, secret)
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
		Uid:        uuid.UUID{},
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		AuthToken:  testAuth,
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid UUID")
	}
}

func Test_StoreNewIdentity_BadPrivateKey(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockCtxMngr{}, secret)
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
		Uid:        testUuid,
		PrivateKey: make([]byte, 32),
		PublicKey:  pubKeyPEM,
		AuthToken:  testAuth,
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid private key")
	}
}

func Test_StoreNewIdentity_NilPrivateKey(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockCtxMngr{}, secret)
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
		Uid:        testUuid,
		PrivateKey: nil,
		PublicKey:  pubKeyPEM,
		AuthToken:  testAuth,
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid private key")
	}
}

func Test_StoreNewIdentity_BadPublicKey(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockCtxMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPEM, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	i := Identity{
		Uid:        testUuid,
		PrivateKey: privKeyPEM,
		PublicKey:  make([]byte, 64),
		AuthToken:  testAuth,
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid public key")
	}
}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockCtxMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPEM, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	i := Identity{
		Uid:        testUuid,
		PrivateKey: privKeyPEM,
		PublicKey:  nil,
		AuthToken:  testAuth,
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid public key")
	}
}

func Test_StoreNewIdentity_NilAuth(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockCtxMngr{}, secret)
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
		Uid:        testUuid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		AuthToken:  "",
	}

	err = p.StoreNewIdentity(nil, i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid auth token")
	}
}

type mockCtxMngr struct {
	id Identity
}

var _ ContextManager = (*mockCtxMngr)(nil)

func (m *mockCtxMngr) StoreNewIdentity(tx interface{}, id Identity) error {
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
	if m.id.PublicKey == nil || !bytes.Equal(m.id.PublicKey, pubKey) {
		return uuid.Nil, ErrNotExist
	}
	return m.id.Uid, nil
}

func (m *mockCtxMngr) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	return nil, nil
}

func (m *mockCtxMngr) CloseTransaction(transactionCtx interface{}, commit bool) error {
	return nil
}

func (m *mockCtxMngr) Close() {}
