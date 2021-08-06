package main

import (
	"testing"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestIdentityHandler_initIdentity(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	argon2idParams := &pw.Argon2idParams{
		Time:    1,
		Memory:  1024,
		Threads: 1,
		KeyLen:  8,
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{}, argon2idParams)
	defer p.Close()

	idHandler := &IdentityHandler{
		Protocol:            p,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	err := p.Crypto.GenerateKey(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = idHandler.InitIdentity(test.Uuid, test.Auth)
	if err != nil {
		t.Fatal(err)
	}

	initializedIdentity, err := p.GetIdentity(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := p.pwHasher.CheckPasswordHash(test.Auth, initializedIdentity.PW)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("initializedIdentity unexpected password")
	}

	data := []byte("test")

	signature, err := p.Sign(test.Uuid, data)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	verified, err := p.Verify(test.Uuid, data, signature)
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

	argon2idParams := &pw.Argon2idParams{
		Time:    1,
		Memory:  1024,
		Threads: 1,
		KeyLen:  8,
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{}, argon2idParams)
	defer p.Close()

	idHandler := &IdentityHandler{
		Protocol:            p,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	err := p.Crypto.GenerateKey(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = idHandler.InitIdentity(test.Uuid, test.Auth)
	if err != nil {
		t.Fatal(err)
	}

	_, err = idHandler.InitIdentity(test.Uuid, test.Auth)
	if err != h.ErrAlreadyInitialized {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrAlreadyInitialized)
	}
}

func TestIdentityHandler_initIdentityBad_ErrUnknown(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	argon2idParams := &pw.Argon2idParams{
		Time:    1,
		Memory:  1024,
		Threads: 1,
		KeyLen:  8,
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{}, argon2idParams)
	defer p.Close()

	idHandler := &IdentityHandler{
		Protocol:            p,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err := idHandler.InitIdentity(test.Uuid, test.Auth)
	if err != h.ErrUnknown {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrUnknown)
	}
}
