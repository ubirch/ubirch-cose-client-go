package main

import (
	"fmt"
	"github.com/google/uuid"
	"math/rand"
	"testing"
)

func TestIdentityHandler_initIdentity(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockCtxMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: mockSubmitKeyRegistration,
		SubmitCSR:             mockSubmitCSR,
		subjectCountry:        "AA",
		subjectOrganization:   "test GmbH",
	}

	_, err = idHandler.initIdentity(testUuid, testAuth)
	if err != nil {
		t.Error(err)
	}
}

func TestIdentityHandler_initIdentityBad(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	p, err := NewProtocol(&mockCtxMngr{}, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: mockSubmitKeyRegistrationBad,
		SubmitCSR:             mockSubmitCSR,
		subjectCountry:        "AA",
		subjectOrganization:   "test GmbH",
	}

	_, err = idHandler.initIdentity(testUuid, testAuth)
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
