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

type RegisterAuth func(uid uuid.UUID, auth string) error

type IdentityHandler struct {
	Protocol *Protocol
	RegisterAuth
	subjectCountry      string
	subjectOrganization string
}

func (i *IdentityHandler) InitIdentity(uid uuid.UUID) (csrPEM []byte, auth string, err error) {
	log.Infof("initialize identity %s", uid)

	err = i.Protocol.IsReady()
	if err != nil {
		return nil, "", err
	}

	initialized, err := i.Protocol.IsInitialized(uid)
	if err != nil {
		return nil, "", fmt.Errorf("could not check if identity is already initialized: %v", err)
	}

	if initialized {
		return nil, "", h.ErrAlreadyInitialized
	}

	// generate a new key pair
	err = i.Protocol.Crypto.GenerateKey(uid)
	if err != nil {
		return nil, "", fmt.Errorf("generating new key for UUID %s failed: %v", uid, err)
	}

	privKeyPEM, err := i.Protocol.LoadPrivateKey(uid)
	if err != nil {
		return nil, "", err
	}

	pubKeyPEM, err := i.Protocol.LoadPublicKey(uid)
	if err != nil {
		return nil, "", err
	}

	csr, err := i.Protocol.Crypto.GetCSR(uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return nil, "", fmt.Errorf("could not generate CSR: %v", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	pw, err := generatePassword()
	if err != nil {
		return nil, "", err
	}

	identity := Identity{
		Uid:        uid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		Auth:       pw,
	}

	ctxForTransaction, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := i.Protocol.StartTransaction(ctxForTransaction)
	if err != nil {
		return nil, "", err
	}

	err = i.Protocol.StoreIdentity(tx, identity)
	if err != nil {
		return nil, "", fmt.Errorf("could not store new identity: %v", err)
	}

	err = i.RegisterAuth(uid, pw)
	if err != nil {
		return nil, "", err
	}

	err = tx.Commit()
	if err != nil {
		return nil, "", fmt.Errorf("commiting transaction to store new identity failed after successful registration at certify-api: %v", err)
	}

	infos := fmt.Sprintf("\"hwDeviceId\":\"%s\"", uid)
	auditlogger.AuditLog("create", "device", infos)

	return csrPEM, pw, nil
}

func (i *IdentityHandler) CreateCSR(uid uuid.UUID) (csrPEM []byte, err error) {
	log.Infof("create CSR for identity %s", uid)

	initialized, err := i.Protocol.IsInitialized(uid)
	if err != nil {
		return nil, fmt.Errorf("could not check if identity is already initialized: %v", err)
	}

	if !initialized {
		return nil, h.ErrUnknown
	}

	csr, err := i.Protocol.Crypto.GetCSR(uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("could not create CSR: %v", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	return csrPEM, nil
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
