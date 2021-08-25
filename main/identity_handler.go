// Copyright (c) 2021 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-cose-client-go/main/auditlogger"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
)

type SubmitKeyRegistration func(uid uuid.UUID, cert []byte, auth string) error
type SubmitCSR func(uid uuid.UUID, csr []byte) error
type RegisterAuth func(uid uuid.UUID, auth string) error

type IdentityHandler struct {
	Protocol *Protocol
	SubmitKeyRegistration
	SubmitCSR
	RegisterAuth
	subjectCountry      string
	subjectOrganization string
}

func (i *IdentityHandler) InitIdentity(uid uuid.UUID) (csrPEM []byte, err error) {
	initialized, err := i.Protocol.isInitialized(uid)
	if err != nil {
		return nil, fmt.Errorf("could not check if identity is already initialized: %v", err)
	}

	if initialized {
		return nil, h.ErrAlreadyInitialized
	}
	log.Infof("initializing new identity %s", uid)

	// generate a new new pair
	privKeyPEM, err := i.Protocol.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating new key for UUID %s failed: %v", uid, err)
	}

	pubKeyPEM, err := i.Protocol.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		return nil, err
	}

	pw, err := generatePassword()
	if err != nil {
		return nil, err
	}

	newIdentity := Identity{
		Uid:        uid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		AuthToken:  pw,
	}

	ctxForTransaction, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := i.Protocol.StartTransaction(ctxForTransaction)
	if err != nil {
		return nil, err
	}

	err = i.Protocol.StoreNewIdentity(tx, newIdentity)
	if err != nil {
		return nil, fmt.Errorf("could not store new identity: %v", err)
	}

	// register public key at the ubirch backend
	csr, err := i.registerPublicKey(privKeyPEM, uid)
	if err != nil {
		return nil, err
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	// register auth token at the certify api
	err = i.RegisterAuth(uid, pw)
	if err != nil {
		return nil, err
	}

	err = i.Protocol.CloseTransaction(tx, Commit)
	if err != nil {
		return nil, fmt.Errorf("commiting transaction to store new identity failed after successful registration at certify-api: %v", err)
	}

	infos := fmt.Sprintf("\"hwDeviceId\":\"%s\"", uid)
	auditlogger.AuditLog("create", "device", infos)

	return csrPEM, nil
}

func (i *IdentityHandler) CreateCSR(uid uuid.UUID) (csrPEM []byte, err error) {
	id, err := i.Protocol.GetIdentity(uid)
	if err == ErrNotExist {
		return nil, h.ErrUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("failed to check for existence of private key: %v", err)
	}

	csr, err := i.Protocol.GetCSR(id.PrivateKey, uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("could not generate CSR: %v", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	return csrPEM, nil
}

func (i *IdentityHandler) registerPublicKey(privKeyPEM []byte, uid uuid.UUID) (csr []byte, err error) {
	keyRegistration, err := i.Protocol.GetSignedKeyRegistration(privKeyPEM, uid)
	if err != nil {
		return nil, fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: key certificate: %s", uid, keyRegistration)

	csr, err = i.Protocol.GetCSR(privKeyPEM, uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("creating CSR for UUID %s failed: %v", uid, err)
	}
	log.Debugf("%s: CSR [der]: %x", uid, csr)

	err = i.SubmitKeyRegistration(uid, keyRegistration, "")
	if err != nil {
		return nil, fmt.Errorf("key registration for UUID %s failed: %v", uid, err)
	}

	go i.submitCSROrLogError(uid, csr)

	return csr, nil
}

func (i *IdentityHandler) submitCSROrLogError(uid uuid.UUID, csr []byte) {
	err := i.SubmitCSR(uid, csr)
	if err != nil {
		log.Errorf("submitting CSR for UUID %s failed: %v", uid, err)
	}
}

// generatePassword generates the base64 string representation of 32 random bytes
// which were created with the Read function of the "crypto/rand" package
func generatePassword() (string, error) {
	pwBytes := make([]byte, 32)
	_, err := rand.Read(pwBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate a random password: %v", err)
	}

	return base64.RawStdEncoding.EncodeToString(pwBytes), nil
}
