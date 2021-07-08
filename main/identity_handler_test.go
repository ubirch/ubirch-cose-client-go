package main

import (
	"testing"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestIdentityHandler_initIdentity(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &mockKeystorer{},
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})

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
		t.Error(err)
	}
}

func TestIdentityHandler_initIdentityBad_ErrAlreadyInitialized(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &mockKeystorer{},
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})

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
		t.Error(err)
	}

	_, err = idHandler.InitIdentity(test.Uuid, test.Auth)
	if err != h.ErrAlreadyInitialized {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrAlreadyInitialized)
	}
}

func TestIdentityHandler_initIdentityBad_ErrUnknown(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &mockKeystorer{},
	}

	p := NewProtocol(cryptoCtx, &mockCtxMngr{})

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
