package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestIdentityHandler_initIdentity(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	err := cryptoCtx.GenerateKey(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	p := NewProtocol(&mockStorageMngr{}, 1, test.Argon2idParams)

	client := &mockRegistrationClient{}

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		Register:            client.registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err = idHandler.InitIdentity(context.Background(), test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	initializedIdentity, err := p.GetIdentity(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := p.pwHasher.CheckPassword(context.Background(), client.Auth, initializedIdentity.Auth)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("initializedIdentity unexpected password")
	}

	pub, err := cryptoCtx.GetPublicKeyPEM(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(initializedIdentity.PublicKeyPEM, pub) {
		t.Error("initializedIdentity unexpected public key")
	}

	data := []byte("test")

	signature, err := cryptoCtx.Sign(test.Uuid, data)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	verified, err := cryptoCtx.Verify(test.Uuid, data, signature)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	if !verified {
		t.Fatal("signature not verifiable")
	}
}

func TestIdentityHandler_initIdentityBad_ErrAlreadyInitialized(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	err := cryptoCtx.GenerateKey(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	p := NewProtocol(&mockStorageMngr{}, 1, test.Argon2idParams)

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		Register:            (&mockRegistrationClient{}).registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err = idHandler.InitIdentity(context.Background(), test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = idHandler.InitIdentity(context.Background(), test.Uuid)
	if err != h.ErrAlreadyInitialized {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrAlreadyInitialized)
	}
}

func TestIdentityHandler_initIdentityBad_ErrUnknown(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	p := NewProtocol(&mockStorageMngr{}, 1, test.Argon2idParams)

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		Register:            (&mockRegistrationClient{}).registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err := idHandler.InitIdentity(context.Background(), test.Uuid)
	if err != h.ErrUnknown {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrUnknown)
	}

	_, err = p.GetIdentity(test.Uuid)
	if err != ErrNotExist {
		t.Errorf("unexpected error: %v, expected: %v", err, ErrNotExist)
	}
}

func TestIdentityHandler_initIdentity_BadRegistration(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	p := NewProtocol(&mockStorageMngr{}, 1, test.Argon2idParams)

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		Register:            (&mockRegistrationClient{}).registerAuthBad,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err := idHandler.InitIdentity(context.Background(), test.Uuid)
	if err == nil {
		t.Errorf("no error after failed registration")
	}

	_, err = p.GetIdentity(test.Uuid)
	if err != ErrNotExist {
		t.Errorf("unexpected error: %v, expected: %v", err, ErrNotExist)
	}
}

type mockRegistrationClient struct {
	Auth string
}

func (m *mockRegistrationClient) registerAuth(uid uuid.UUID, auth string) error {
	m.Auth = auth
	return nil
}

func (m *mockRegistrationClient) registerAuthBad(uid uuid.UUID, auth string) error {
	return test.Error
}
