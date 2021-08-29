package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestIdentityHandler_InitIdentity(t *testing.T) {
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
		RegisterAuth:        client.registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	csrPEM, auth, err := idHandler.InitIdentity(context.Background(), test.Uuid)
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

	pub, err := cryptoCtx.GetPublicKeyPEM(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pub, initializedIdentity.PublicKeyPEM) {
		t.Error("initializedIdentity unexpected public key")
	}

	csrPublicKey, err := cryptoCtx.EncodePublicKey(csr.PublicKey)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(csrPublicKey, initializedIdentity.PublicKeyPEM) {
			t.Errorf("public key in CSR does not match initializedIdentity.PublicKey")
		}
	}

	if auth != client.Auth {
		t.Error("auth token returned by InitIdentity not equal to registered auth token")
	}

	ok, err := p.PwHasher.CheckPassword(context.Background(), client.Auth, initializedIdentity.Auth)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Error("initializedIdentity unexpected password")
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
		t.Error("signature not verifiable")
	}
}

func TestIdentityHandler_InitIdentityBad_ErrAlreadyInitialized(t *testing.T) {
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
		RegisterAuth:        (&mockRegistrationClient{}).registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, _, err = idHandler.InitIdentity(context.Background(), test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = idHandler.InitIdentity(context.Background(), test.Uuid)
	if err != h.ErrAlreadyInitialized {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrAlreadyInitialized)
	}
}

func TestIdentityHandler_InitIdentityBad_ErrUnknown(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	p := NewProtocol(&mockStorageMngr{}, 1, test.Argon2idParams)

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		RegisterAuth:        (&mockRegistrationClient{}).registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, _, err := idHandler.InitIdentity(context.Background(), test.Uuid)
	if err != h.ErrUnknown {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrUnknown)
	}

	_, err = p.GetIdentity(test.Uuid)
	if err != ErrNotExist {
		t.Errorf("unexpected error: %v, expected: %v", err, ErrNotExist)
	}
}

func TestIdentityHandler_InitIdentity_BadRegistration(t *testing.T) {
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
		RegisterAuth:        (&mockRegistrationClient{}).registerAuthBad,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, _, err = idHandler.InitIdentity(context.Background(), test.Uuid)
	if err != test.Error {
		t.Errorf("unexpected error: %v, expected: %v", err, test.Error)
	}

	_, err = p.GetIdentity(test.Uuid)
	if err != ErrNotExist {
		t.Errorf("unexpected error: %v, expected: %v", err, ErrNotExist)
	}
}

func TestIdentityHandler_CreateCSR(t *testing.T) {
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
		RegisterAuth:        (&mockRegistrationClient{}).registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, _, err = idHandler.InitIdentity(context.Background(), test.Uuid)
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

	pub, err := cryptoCtx.EncodePublicKey(csr.PublicKey)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(pub, initializedIdentity.PublicKeyPEM) {
			t.Errorf("public key in CSR does not match initializedIdentity.PublicKey")
		}
	}
}

func TestIdentityHandler_CreateCSR_Unknown(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	p := NewProtocol(&mockStorageMngr{}, 1, test.Argon2idParams)

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err := idHandler.CreateCSR(test.Uuid)
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
