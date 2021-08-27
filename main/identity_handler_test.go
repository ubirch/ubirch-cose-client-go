package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"testing"

	"github.com/google/uuid"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestIdentityHandler_InitIdentity(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	client := &mockRegistrationClient{}

	idHandler := &IdentityHandler{
		Protocol:            p,
		RegisterAuth:        client.registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	csrPEM, err := idHandler.InitIdentity(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Error("failed to decode PEM block containing CSR")
	}
	if len(rest) != 0 {
		t.Errorf("rest: %q", rest)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Error(err)
	}

	initializedIdentity, err := p.GetIdentity(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := p.Crypto.EncodePublicKey(csr.PublicKey)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(pub, initializedIdentity.PublicKey) {
			t.Errorf("public key in CSR does not match initializedIdentity.PublicKey")
		}
	}

	if client.Auth != initializedIdentity.AuthToken {
		t.Error("initializedIdentity unexpected AuthToken")
	}

	data := []byte("test")

	signature, err := p.Crypto.Sign(initializedIdentity.PrivateKey, data)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	verified, err := p.Crypto.Verify(initializedIdentity.PublicKey, data, signature)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	if !verified {
		t.Error("signature not verifiable")
	}
}

func TestIdentityHandler_InitIdentityBad_ErrAlreadyInitialized(t *testing.T) {
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

func TestIdentityHandler_InitIdentity_BadRegistration(t *testing.T) {
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
		t.Errorf("unexpected error: %v, expected: %v", err, test.Error)
	}

	_, err = p.GetIdentity(test.Uuid)
	if err != ErrNotExist {
		t.Errorf("unexpected error: %v, expected: %v", err, ErrNotExist)
	}
}

func TestIdentityHandler_CreateCSR(t *testing.T) {
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

	csrPEM, err := idHandler.CreateCSR(test.Uuid)
	if err != nil {
		t.Error(err)
	}

	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Error("failed to decode PEM block containing CSR")
	}
	if len(rest) != 0 {
		t.Errorf("rest: %q", rest)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Error(err)
	}

	initializedIdentity, err := p.GetIdentity(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := p.Crypto.EncodePublicKey(csr.PublicKey)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(pub, initializedIdentity.PublicKey) {
			t.Errorf("public key in CSR does not match initializedIdentity.PublicKey")
		}
	}
}

func TestIdentityHandler_CreateCSR_Unknown(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockStorageMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}

	idHandler := &IdentityHandler{
		Protocol:            p,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err = idHandler.CreateCSR(test.Uuid)
	if err != h.ErrUnknown {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrUnknown)
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
