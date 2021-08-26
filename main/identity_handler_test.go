package main

import (
	"math/rand"
	"testing"

	"github.com/google/uuid"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestIdentityHandler_initIdentity(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	registrationClient := &mockRegistrationClient{}

	idHandler := &IdentityHandler{
		Protocol:            p,
		RegisterAuth:        registrationClient.registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err = idHandler.InitIdentity(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	initializedIdentity, err := p.GetIdentity(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	if initializedIdentity.AuthToken != registrationClient.Auth {
		t.Error("initializedIdentity unexpected AuthToken")
	}

	data := []byte("test")

	signature, err := p.Sign(initializedIdentity.PrivateKey, data)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	verified, err := p.Verify(initializedIdentity.PublicKey, data, signature)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	if !verified {
		t.Error("signature not verifiable")
	}
}

func TestIdentityHandler_initIdentityBad_ErrAlreadyInitialized(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	idHandler := &IdentityHandler{
		Protocol:            p,
		RegisterAuth:        (&mockRegistrationClient{}).registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err = idHandler.InitIdentity(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = idHandler.InitIdentity(test.Uuid)
	if err != h.ErrAlreadyInitialized {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrAlreadyInitialized)
	}
}

func TestIdentityHandler_initIdentity_BadRegistration(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	idHandler := &IdentityHandler{
		Protocol:            p,
		RegisterAuth:        (&mockRegistrationClient{}).registerAuthBad,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err = idHandler.InitIdentity(test.Uuid)
	if err != test.Error {
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

func (m *mockRegistrationClient) registerAuthBad(uuid.UUID, string) error {
	return test.Error
}
