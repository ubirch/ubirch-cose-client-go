// Copyright (c) 2019-2020 ubirch GmbH
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
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/auditlogger"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

type SubmitKeyRegistration func(uid uuid.UUID, cert []byte, auth string) error
type SubmitCSR func(uid uuid.UUID, csr []byte) error

type IdentityHandler struct {
	crypto     ubirch.Crypto
	ctxManager ContextManager
	SubmitKeyRegistration
	SubmitCSR
	subjectCountry      string
	subjectOrganization string
}

type Identity struct {
	Uid        uuid.UUID `json:"uuid"`
	PrivateKey []byte    `json:"privKey"`
	PublicKey  []byte    `json:"pubKey"`
	AuthToken  string    `json:"token"`
}

func (i *IdentityHandler) initIdentity(uid uuid.UUID, auth string) (csr []byte, err error) {
	log.Infof("initializing new identity %s", uid)

	// generate a new new pair
	privKeyPEM, err := i.crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating new key for UUID %s failed: %v", uid, err)
	}

	pubKeyPEM, err := i.crypto.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		return nil, err
	}

	newIdentity := Identity{
		Uid:        uid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		AuthToken:  auth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := i.ctxManager.StartTransaction(ctx)
	if err != nil {
		return nil, err
	}

	err = i.ctxManager.StoreNewIdentity(tx, newIdentity)
	if err != nil {
		return nil, err
	}

	// register public key at the ubirch backend
	csr, err = i.registerPublicKey(privKeyPEM, uid)
	if err != nil {
		return nil, err
	}

	err = i.ctxManager.CloseTransaction(tx, Commit)
	if err != nil {
		return nil, err
	}

	infos := fmt.Sprintf("\"hwDeviceId\":\"%s\"", uid)
	auditlogger.AuditLog("create", "device", infos)

	return csr, nil
}

func (i *IdentityHandler) registerPublicKey(privKeyPEM []byte, uid uuid.UUID) (csr []byte, err error) {
	keyRegistration, err := i.crypto.GetSignedKeyRegistration(privKeyPEM, uid)
	if err != nil {
		return nil, fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: key certificate: %s", uid, keyRegistration)

	csr, err = i.crypto.GetCSR(privKeyPEM, uid, i.subjectCountry, i.subjectOrganization)
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
