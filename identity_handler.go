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
	"fmt"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type IdentityHandler struct {
	protocol            *ExtendedProtocol
	client              *Client
	subjectCountry      string
	subjectOrganization string
}

func (i *IdentityHandler) initIdentities(identities map[string]uuid.UUID) error {
	// create and register keys for identities
	log.Infof("initializing %d identities...", len(identities))
	for _, uid := range identities {
		err := i.initIdentity(uid)
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *IdentityHandler) initIdentity(uid uuid.UUID) error {
	err := i.protocol.StartTransaction(uid)
	if err != nil {
		return err
	}

	err = i.initKeys(uid)
	if err != nil {
		ctxErr := i.protocol.EndTransaction(uid, false)
		if ctxErr != nil {
			log.Error(err)
			return ctxErr
		}
		return err
	}

	ctxErr := i.protocol.EndTransaction(uid, true)
	if ctxErr != nil {
		return fmt.Errorf("can not end transaction: %v", ctxErr)
	}

	return nil
}

func (i *IdentityHandler) initKeys(uid uuid.UUID) error {
	// check if identity is already initialized
	exists := i.protocol.Exists(uid)
	if exists {
		return nil
	}

	log.Infof("%s: initializing new identity", uid)

	// generate a new private key
	log.Debugf("%s: generating new key pair", uid)
	privKeyPEM, err := i.protocol.GenerateKey()
	if err != nil {
		return fmt.Errorf("generating new key for UUID %s failed: %v", uid, err)
	}

	// set private key
	err = i.protocol.SetPrivateKey(uid, privKeyPEM)
	if err != nil {
		return err
	}

	// set public key
	pubKeyPEM, err := i.protocol.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		return err
	}

	err = i.protocol.SetPublicKey(uid, pubKeyPEM)
	if err != nil {
		return err
	}

	// register public key at the ubirch backend
	return i.registerPublicKey(privKeyPEM, uid)
}

func (i *IdentityHandler) registerPublicKey(privKeyPEM []byte, uid uuid.UUID) error {
	cert, err := i.protocol.GetSignedKeyRegistration(privKeyPEM, uid)
	if err != nil {
		return fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: key certificate: %s", uid, cert)

	err = i.client.submitKeyRegistration(uid, cert)
	if err != nil {
		return fmt.Errorf("key registration for UUID %s failed: %v", uid, err)
	}

	go i.sendCSROrLogError(privKeyPEM, uid)

	return nil
}
func (i *IdentityHandler) sendCSROrLogError(privKeyPEM []byte, uid uuid.UUID) {
	err := i.sendCSR(privKeyPEM, uid)
	if err != nil {
		log.Error(err)
	}
}

// sendCSR  generates and submits a signed a X.509 Certificate Signing Request for the public key
func (i *IdentityHandler) sendCSR(privKeyPEM []byte, uid uuid.UUID) error {
	csr, err := i.protocol.GetCSR(privKeyPEM, uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return fmt.Errorf("creating CSR for UUID %s failed: %v", uid, err)
	}
	log.Debugf("%s: CSR [der]: %x", uid, csr)

	err = i.client.submitCSR(uid, csr)
	if err != nil {
		return fmt.Errorf("submitting CSR for UUID %s failed: %v", uid, err)
	}

	return nil
}
