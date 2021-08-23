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
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
)

type IdentityHandler struct {
	*Protocol
	ubirch.Crypto
	subjectCountry      string
	subjectOrganization string
}

func (i *IdentityHandler) InitIdentity(ctx context.Context, uid uuid.UUID) ([]byte, error) {
	log.Infof("initializing identity %s", uid)

	initialized, err := i.isInitialized(uid)
	if err != nil {
		return nil, fmt.Errorf("could not check if identity is already initialized: %v", err)
	}

	if initialized {
		return nil, h.ErrAlreadyInitialized
	}

	keyExists, err := i.PrivateKeyExists(uid)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existence of private key: %v", err)
	}

	if !keyExists {
		return nil, h.ErrUnknown
	}

	csr, err := i.GetCSR(uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("could not generate CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	pubKeyPEM, err := i.GetPublicKeyPEM(uid)
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %v", err)
	}

	pw, err := generatePassword()
	if err != nil {
		return nil, err
	}

	pwHash, err := i.pwHasher.GeneratePasswordHash(ctx, pw, i.pwHasherParams)
	if err != nil {
		return nil, err
	}

	identity := Identity{
		Uid:          uid,
		PublicKeyPEM: pubKeyPEM,
		Auth:         pwHash,
	}

	err = i.StoreNewIdentity(identity)
	if err != nil {
		return nil, fmt.Errorf("could not store new identity: %v", err)
	}

	infos := fmt.Sprintf("\"hwDeviceId\":\"%s\"", uid)
	auditlogger.AuditLog("create", "device", infos)

	return csrPEM, nil
}

func (i *IdentityHandler) CreateCSR(uid uuid.UUID) ([]byte, error) {
	keyExists, err := i.PrivateKeyExists(uid)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existence of private key: %v", err)
	}

	if !keyExists {
		return nil, h.ErrUnknown
	}

	csr, err := i.GetCSR(uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("could not generate CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

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
