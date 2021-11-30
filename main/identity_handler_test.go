package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
)

func TestIdentityHandler_InitIdentity(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	err := cryptoCtx.GenerateKey(testUuid)
	require.NoError(t, err)

	p := NewProtocol(&mockStorageMngr{}, &config.Config{})

	client := &mockRegistrationClient{}

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		RegisterAuth:        client.registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	csrPEM, auth, err := idHandler.InitIdentity(testUuid)
	require.NoError(t, err)

	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Error("failed to decode PEM block containing CSR")
	}
	if len(rest) != 0 {
		t.Errorf("rest: %q", rest)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	initializedIdentity, err := p.LoadIdentity(testUuid)
	require.NoError(t, err)

	pub, err := cryptoCtx.GetPublicKeyPEM(testUuid)
	require.NoError(t, err)
	assert.Equal(t, initializedIdentity.PublicKeyPEM, pub)

	csrPublicKey, err := cryptoCtx.EncodePublicKey(csr.PublicKey)
	require.NoError(t, err)
	assert.Equalf(t, initializedIdentity.PublicKeyPEM, csrPublicKey, "public key in CSR does not match initializedIdentity.PublicKey")
	assert.Equalf(t, auth, client.Auth, "auth token returned by InitIdentity not equal to registered auth token")

	_, ok, err := p.pwHasher.CheckPassword(context.Background(), initializedIdentity.Auth, client.Auth)
	require.NoError(t, err)
	assert.True(t, ok)

	data := []byte("test")

	signature, err := cryptoCtx.Sign(testUuid, data)
	require.NoError(t, err)

	verified, err := cryptoCtx.Verify(testUuid, data, signature)
	require.NoError(t, err)
	assert.Truef(t, verified, "signature not verifiable")
}

func TestIdentityHandler_InitIdentityBad_ErrAlreadyInitialized(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	err := cryptoCtx.GenerateKey(testUuid)
	require.NoError(t, err)

	p := NewProtocol(&mockStorageMngr{}, &config.Config{})

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		RegisterAuth:        (&mockRegistrationClient{}).registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, _, err = idHandler.InitIdentity(testUuid)
	require.NoError(t, err)

	_, _, err = idHandler.InitIdentity(testUuid)
	assert.Equal(t, h.ErrAlreadyInitialized, err)
}

func TestIdentityHandler_InitIdentityBad_ErrUnknown(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p := NewProtocol(&mockStorageMngr{}, &config.Config{})

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		RegisterAuth:        (&mockRegistrationClient{}).registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, _, err := idHandler.InitIdentity(testUuid)
	assert.Equal(t, h.ErrUnknown, err)

	_, err = p.LoadIdentity(testUuid)
	assert.Equal(t, ErrNotExist, err)
}

func TestIdentityHandler_InitIdentity_BadRegistration(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	err := cryptoCtx.GenerateKey(testUuid)
	require.NoError(t, err)

	p := NewProtocol(&mockStorageMngr{}, &config.Config{})

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		RegisterAuth:        (&mockRegistrationClient{}).registerAuthBad,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, _, err = idHandler.InitIdentity(testUuid)
	assert.Equal(t, testError, err)

	_, err = p.LoadIdentity(testUuid)
	assert.Equal(t, ErrNotExist, err)
}

func TestIdentityHandler_CreateCSR(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	err := cryptoCtx.GenerateKey(testUuid)
	require.NoError(t, err)

	p := NewProtocol(&mockStorageMngr{}, &config.Config{})

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		RegisterAuth:        (&mockRegistrationClient{}).registerAuth,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, _, err = idHandler.InitIdentity(testUuid)
	require.NoError(t, err)

	csrPEM, err := idHandler.CreateCSR(testUuid)
	require.NoError(t, err)

	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Error("failed to decode PEM block containing CSR")
	}
	if len(rest) != 0 {
		t.Errorf("rest: %q", rest)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	initializedIdentity, err := p.LoadIdentity(testUuid)
	require.NoError(t, err)

	pub, err := cryptoCtx.EncodePublicKey(csr.PublicKey)
	require.NoError(t, err)
	assert.Equalf(t, initializedIdentity.PublicKeyPEM, pub, "public key in CSR does not match initializedIdentity.PublicKey")
}

func TestIdentityHandler_CreateCSR_Unknown(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	p := NewProtocol(&mockStorageMngr{}, &config.Config{})

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err := idHandler.CreateCSR(testUuid)
	assert.Equal(t, h.ErrUnknown, err)
}

type mockRegistrationClient struct {
	Auth string
}

func (m *mockRegistrationClient) registerAuth(uid uuid.UUID, auth string) error {
	m.Auth = auth
	return nil
}

func (m *mockRegistrationClient) registerAuthBad(uuid.UUID, string) error {
	return testError
}
