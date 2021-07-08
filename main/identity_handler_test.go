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
	idHandler := &IdentityHandler{
		protocol:            NewProtocol(cryptoCtx, &mockCtxMngr{}),
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err := idHandler.InitIdentity(test.Uuid, test.Auth)
	if err != nil {
		t.Error(err)
	}
}

func TestIdentityHandler_initIdentityBad_ErrAlreadyInitialized(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &mockKeystorer{},
	}
	idHandler := &IdentityHandler{
		protocol:            NewProtocol(cryptoCtx, &mockCtxMngr{}),
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err := idHandler.InitIdentity(test.Uuid, test.Auth)
	if err != h.ErrAlreadyInitialized {
		t.Errorf("unexpected return value: %v, expected: %v", err, h.ErrAlreadyInitialized)
	}
}

func TestIdentityHandler_initIdentityBad_ErrUnknown(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &mockKeystorer{},
	}
	idHandler := &IdentityHandler{
		protocol:            NewProtocol(cryptoCtx, &mockCtxMngr{}),
		subjectCountry:      "AA",
		subjectOrganization: "test GmbH",
	}

	_, err := idHandler.InitIdentity(test.Uuid, test.Auth)
	if err != h.ErrUnknown {
		t.Errorf("unexpected return value: %v, expected: %v", err, h.ErrUnknown)
	}
}
