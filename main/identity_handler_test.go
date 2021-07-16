package main

import (
	"testing"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestIdentityHandler_initIdentity(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})
	defer p.Close()

	idHandler := &IdentityHandler{
		protocol:            p,
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

	if initializedIdentity.AuthToken != test.Auth {
		t.Error("initializedIdentity unexpected AuthToken")
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

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})
	defer p.Close()

	idHandler := &IdentityHandler{
		protocol:            p,
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

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})
	defer p.Close()

	idHandler := &IdentityHandler{
		protocol:            p,
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err := idHandler.InitIdentity(test.Uuid, test.Auth)
	if err != h.ErrUnknown {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrUnknown)
	}
}
