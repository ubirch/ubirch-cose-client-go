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
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-cose-client-go/main/auditlogger"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
)

type IdentityHandler struct {
	protocol            *Protocol
	subjectCountry      string
	subjectOrganization string
}

func (i *IdentityHandler) InitIdentity(uid uuid.UUID, auth string) (csrPEM []byte, err error) {
	log.Infof("initializing identity %s", uid)

	initialized, err := i.protocol.isInitialized(uid)
	if err != nil {
		return nil, fmt.Errorf("could not check if identity is already initialized: %v", err)
	}

	if initialized {
		return nil, h.ErrAlreadyInitialized
	}

	csrPEM, err = i.GetCSR(uid)
	if err != nil {
		return nil, err
	}

	pubKeyPEM, err := i.protocol.GetPublicKeyPEM(uid)
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %v", err)
	}

	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}
	derivedKey := i.protocol.keyDerivator.GetDerivedKey([]byte(auth), salt)

	identity := Identity{
		Uid:          uid,
		PublicKeyPEM: pubKeyPEM,
		PW: &Password{
			DerivedKey: derivedKey,
			Salt:       salt,
		},
	}

	err = i.protocol.StoreNewIdentity(identity)
	if err != nil {
		return nil, fmt.Errorf("could not store new identity: %v", err)
	}

	infos := fmt.Sprintf("\"hwDeviceId\":\"%s\"", uid)
	auditlogger.AuditLog("create", "device", infos)

	return csrPEM, nil
}

func (i *IdentityHandler) GetCSR(uid uuid.UUID) (csrPEM []byte, err error) {
	keyExists, err := i.protocol.PrivateKeyExists(uid)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existence of private key: %v", err)
	}
	if !keyExists {
		return nil, h.ErrUnknown
	}

	csr, err := i.protocol.GetCSR(uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("could not generate CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}

//func (i *IdentityHandler) GetCSRAndUpdatePublicKey(uid uuid.UUID) (csrPEM []byte, err error) {
//	csrPEM, err = i.GetCSR(uid)
//	if err != nil {
//		return nil, err
//	}
//
//	pubKeyBytes, err := i.protocol.GetPublicKey(uid)
//	if err != nil {
//		return nil, fmt.Errorf("could not get public key: %v", err)
//	}
//
//	pubKeyPEM, err := i.protocol.PublicKeyBytesToPEM(pubKeyBytes)
//	if err != nil {
//		return nil, fmt.Errorf("could not convert public key bytes to PEM: %v", err)
//	}
//
//	// todo update public key in database
//
//	return csrPEM, nil
//}
