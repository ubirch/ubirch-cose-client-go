package main

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/encrypters"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"math/rand"
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
		Uid:        uid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		AuthToken:  "password1234",
	}

	err = p.StoreNewIdentity(nil, testIdentity)
	if err != nil {
		t.Fatal(err)
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

type mockCtxMngr struct {
	id Identity
}

var _ ContextManager = (*mockCtxMngr)(nil)

func (m *mockCtxMngr) StoreNewIdentity(tx interface{}, id Identity) error {
	m.id = id
	return nil
}

func (m *mockCtxMngr) GetIdentity(uid uuid.UUID) (*Identity, error) {
	return &m.id, nil
}

func (m *mockCtxMngr) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	panic("implement me")
}

func (m *mockCtxMngr) CloseTransaction(transactionCtx interface{}, commit bool) error {
	panic("implement me")
}

func (m *mockCtxMngr) ExistsPrivateKey(uid uuid.UUID) (bool, error) {
	panic("implement me")
}

func (m *mockCtxMngr) GetPrivateKey(uid uuid.UUID) (privKey []byte, err error) {
	panic("implement me")
}

func (m *mockCtxMngr) GetPublicKey(uid uuid.UUID) (pubKey []byte, err error) {
	panic("implement me")
}

func (m *mockCtxMngr) GetAuthToken(uid uuid.UUID) (string, error) {
	panic("implement me")
}

func (m *mockCtxMngr) GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error) {
	panic("implement me")
}
