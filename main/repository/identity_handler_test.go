package repository

import (
	"context"
	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
	"testing"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server/helper"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

var Argon2idParams = &pw.Argon2idParams{Time: 1, Memory: 1, Threads: 1, KeyLen: 1}

func TestIdentityHandler_initIdentity(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	err := cryptoCtx.GenerateKey(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	p := NewProtocol(&mockStorageMngr{}, 1, Argon2idParams)

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		SubjectCountry:      "AA",
		SubjectOrganization: "test GmbH",
	}

	_, err = idHandler.InitIdentity(context.Background(), test.Uuid, test.Auth)
	if err != nil {
		t.Fatal(err)
	}

	initializedIdentity, err := p.GetIdentity(test.Uuid)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := p.PwHasher.CheckPassword(context.Background(), test.Auth, initializedIdentity.Auth)
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

	p := NewProtocol(&mockStorageMngr{}, 1, Argon2idParams)

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		SubjectCountry:      "AA",
		SubjectOrganization: "test GmbH",
	}

	_, err = idHandler.InitIdentity(context.Background(), test.Uuid, test.Auth)
	if err != nil {
		t.Fatal(err)
	}

	_, err = idHandler.InitIdentity(context.Background(), test.Uuid, test.Auth)
	if err != h.ErrAlreadyInitialized {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrAlreadyInitialized)
	}
}

func TestIdentityHandler_initIdentityBad_ErrUnknown(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	p := NewProtocol(&mockStorageMngr{}, 1, Argon2idParams)

	idHandler := &IdentityHandler{
		Protocol:            p,
		Crypto:              cryptoCtx,
		SubjectCountry:      "AA",
		SubjectOrganization: "test GmbH",
	}

	_, err := idHandler.InitIdentity(context.Background(), test.Uuid, test.Auth)
	if err != h.ErrUnknown {
		t.Errorf("unexpected error: %v, expected: %v", err, h.ErrUnknown)
	}
}
