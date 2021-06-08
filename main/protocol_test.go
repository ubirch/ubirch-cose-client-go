package main

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/encrypters"

	log "github.com/sirupsen/logrus"
)

var (
	saltBase64 = "Vc5UxiZbtzvS+XY7thLauvyH6cIyVK6SNAceIDzYpqM="
	auth       = "password123"
	notAuth    = "!password123"
)

func TestProtocol_CheckAuthToken(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString(saltBase64)

	p := &Protocol{
		ctxManager:   &mockCtxMngr{},
		keyDerivator: encrypters.NewDefaultKeyDerivator(salt),
	}

	err := p.SetAuthToken(nil, uuid.Nil, auth)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := p.CheckAuthToken(uuid.Nil, auth)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		log.Error("check of correct auth failed")
	}

	ok, err = p.CheckAuthToken(uuid.Nil, notAuth)
	if err != nil {
		t.Fatal(err)
	}

	if ok {
		log.Error("check of incorrect auth succeeded")
	}
}

type mockCtxMngr struct {
	auth string
}

func (t *mockCtxMngr) SetAuthToken(transactionCtx interface{}, uid uuid.UUID, authToken string) error {
	t.auth = authToken
	return nil
}

func (t *mockCtxMngr) GetAuthToken(uid uuid.UUID) (string, error) {
	return t.auth, nil
}

func (t *mockCtxMngr) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	panic("implement me")
}

func (t *mockCtxMngr) CloseTransaction(transactionCtx interface{}, commit bool) error {
	panic("implement me")
}

func (t *mockCtxMngr) StoreNewIdentity(tx interface{}, id Identity) error {
	panic("implement me")
}

func (t *mockCtxMngr) ExistsPrivateKey(uid uuid.UUID) (bool, error) {
	panic("implement me")
}

func (t *mockCtxMngr) GetPrivateKey(uid uuid.UUID) (privKey []byte, err error) {
	panic("implement me")
}

func (t *mockCtxMngr) ExistsPublicKey(uid uuid.UUID) (bool, error) {
	panic("implement me")
}

func (t *mockCtxMngr) GetPublicKey(uid uuid.UUID) (pubKey []byte, err error) {
	panic("implement me")
}

func (t *mockCtxMngr) ExistsUuidForPublicKey(pubKey []byte) (bool, error) {
	panic("implement me")
}

func (t *mockCtxMngr) GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error) {
	panic("implement me")
}

var _ ContextManager = (*mockCtxMngr)(nil)
