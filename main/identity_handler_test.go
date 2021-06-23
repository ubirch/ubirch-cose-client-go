package main

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"testing"
)

func TestIdentityHandler_initIdentity(t *testing.T) {
	idHandler := &IdentityHandler{
		crypto:                &ubirch.ECDSACryptoContext{},
		ctxManager:            &mockCtxMngr{},
		SubmitKeyRegistration: mockSubmitKeyRegistration,
		SubmitCSR:             mockSubmitCSR,
		subjectCountry:        "AA",
		subjectOrganization:   "test GmbH",
	}

	_, err := idHandler.initIdentity(uid, "password123")
	if err != nil {
		t.Error(err)
	}
}

func TestIdentityHandler_initIdentityBad(t *testing.T) {
	idHandler := &IdentityHandler{
		crypto:                &ubirch.ECDSACryptoContext{},
		ctxManager:            &mockCtxMngr{},
		SubmitKeyRegistration: mockSubmitKeyRegistrationBad,
		SubmitCSR:             mockSubmitCSR,
		subjectCountry:        "AA",
		subjectOrganization:   "test GmbH",
	}

	_, err := idHandler.initIdentity(uid, "password123")
	if err == nil {
		t.Error("no error returned")
	}
}

func mockSubmitKeyRegistration(uid uuid.UUID, cert []byte, auth string) error {
	return nil
}

func mockSubmitKeyRegistrationBad(uid uuid.UUID, cert []byte, auth string) error {
	return fmt.Errorf("test error")
}

func mockSubmitCSR(uid uuid.UUID, csr []byte) error {
	return nil
}
