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
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-cose-client-go/main/auditlogger"

	log "github.com/sirupsen/logrus"
)

type IdentityHandler struct {
	*Protocol
	subjectCountry      string
	subjectOrganization string
}

type Identity struct {
	Uid       uuid.UUID `json:"uuid"`
	PublicKey []byte    `json:"pubKey"`
	AuthToken string    `json:"token"`
}

func (i *IdentityHandler) initIdentity(uid uuid.UUID, auth string) (csrPEM []byte, err error, code int) {
	log.Infof("initializing identity %s", uid)

	initialized, err := i.Initialized(uid)
	if err != nil {
		return nil, fmt.Errorf("failed to check if identity %s is already initialized: %v", uid, err), http.StatusInternalServerError
	}

	if initialized {
		return nil, fmt.Errorf("identity %s already registered", uid), http.StatusConflict
	}

	keyExistsInHSM, err := i.PrivateKeyExists(uid)
	if err != nil {
		return nil, fmt.Errorf("failed to check for private key of %s in HSM: %v", uid, err), http.StatusInternalServerError
	}

	if !keyExistsInHSM {
		return nil, fmt.Errorf("no private key found for %s in HSM", uid), http.StatusBadRequest
	}

	pubKeyBytes, err := i.GetPublicKey(uid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key of %s from HSM: %v", uid, err), http.StatusInternalServerError
	}

	pubKeyPEM, err := i.PublicKeyBytesToPEM(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("could not convert public key if %s bytes to PEM: %v", uid, err), http.StatusInternalServerError
	}

	csr, err := i.GetCSR(uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("could not generate CSR for %s: %v", uid, err), http.StatusInternalServerError
	}

	identity := Identity{
		Uid:       uid,
		PublicKey: pubKeyPEM,
		AuthToken: auth,
	}

	err = i.StoreNewIdentity(identity)
	if err != nil {
		return nil, fmt.Errorf("could not store new identity: %v", err), http.StatusInternalServerError
	}

	infos := fmt.Sprintf("\"hwDeviceId\":\"%s\"", uid)
	auditlogger.AuditLog("create", "device", infos)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil, http.StatusOK
}
