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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/adapters/encrypters"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"sync"
)

const SkidLen = 8

type Protocol struct {
	ubirch.Crypto
	*ExtendedClient
	ctxManager   ContextManager
	keyEncrypter *encrypters.KeyEncrypter

	skidStore      map[uuid.UUID][]byte
	skidStoreMutex *sync.RWMutex
}

// Ensure Protocol implements the ContextManager interface
var _ ContextManager = (*Protocol)(nil)

func NewProtocol(ctxManager ContextManager, secret []byte, client *ExtendedClient) (*Protocol, error) {
	crypto := &ubirch.ECDSACryptoContext{}

	enc, err := encrypters.NewKeyEncrypter(secret, crypto)
	if err != nil {
		return nil, err
	}

	return &Protocol{
		Crypto:         crypto,
		ExtendedClient: client,
		ctxManager:     ctxManager,
		keyEncrypter:   enc,

		skidStore:      map[uuid.UUID][]byte{},
		skidStoreMutex: &sync.RWMutex{},
	}, nil
}

func (p *Protocol) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	return p.ctxManager.StartTransaction(ctx)
}

func (p *Protocol) StartTransactionWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, err error) {
	return p.ctxManager.StartTransactionWithLock(ctx, uid)
}

func (p *Protocol) CloseTransaction(tx interface{}, commit bool) error {
	return p.ctxManager.CloseTransaction(tx, commit)
}

func (p *Protocol) ExistsPrivateKey(uid uuid.UUID) (bool, error) {
	return p.ctxManager.ExistsPrivateKey(uid)
}

func (p *Protocol) StoreNewIdentity(tx interface{}, i Identity) error {
	// check validity of identity attributes
	err := p.checkIdentityAttributes(&i)
	if err != nil {
		return err
	}

	// encrypt private key
	i.PrivateKey, err = p.keyEncrypter.Encrypt(i.PrivateKey)
	if err != nil {
		return err
	}

	// store public key raw bytes
	i.PublicKey, err = p.PublicKeyPEMToBytes(i.PublicKey)
	if err != nil {
		return err
	}

	return p.ctxManager.StoreNewIdentity(tx, i)
}

//func (p *Protocol) SetPrivateKey(uid uuid.UUID, privateKeyPem []byte) error {
//	exists, err := p.ExistsPrivateKey(uid)
//	if err != nil {
//		return err
//	}
//	if exists {
//		return ErrExists
//	}
//
//	encryptedPrivateKey, err := p.keyEncrypter.Encrypt(privateKeyPem)
//	if err != nil {
//		return err
//	}
//
//	return p.ctxManager.SetPrivateKey(nil, uid, encryptedPrivateKey)
//}

func (p *Protocol) GetPrivateKey(uid uuid.UUID) (privateKeyPem []byte, err error) {
	encryptedPrivateKey, err := p.ctxManager.GetPrivateKey(uid)
	if err != nil {
		return nil, err
	}

	return p.keyEncrypter.Decrypt(encryptedPrivateKey)
}

func (p *Protocol) ExistsPublicKey(uid uuid.UUID) (bool, error) {
	return p.ctxManager.ExistsPublicKey(uid)
}

//func (p *Protocol) SetPublicKey(uid uuid.UUID, publicKeyPEM []byte) error {
//	publicKeyBytes, err := p.PublicKeyPEMToBytes(publicKeyPEM)
//	if err != nil {
//		return err
//	}
//
//	return p.ctxManager.SetPublicKey(nil, uid, publicKeyBytes)
//}

func (p *Protocol) GetPublicKey(uid uuid.UUID) (publicKeyPEM []byte, err error) {
	publicKeyBytes, err := p.ctxManager.GetPublicKey(uid)
	if err != nil {
		return nil, err
	}

	return p.PublicKeyBytesToPEM(publicKeyBytes)
}

func (p *Protocol) GetAuthToken(uid uuid.UUID) (string, error) {
	authToken, err := p.ctxManager.GetAuthToken(uid)
	if err != nil {
		return "", err
	}

	if len(authToken) == 0 {
		return "", ErrNotExist
	}

	return authToken, nil
}

func (p *Protocol) checkIdentityAttributes(i *Identity) error {
	if len(i.PrivateKey) == 0 {
		return fmt.Errorf("empty private key")
	}

	if len(i.PublicKey) == 0 {
		return fmt.Errorf("empty public key")
	}

	if len(i.AuthToken) == 0 {
		return fmt.Errorf("empty auth token")
	}

	return nil
}

func (p *Protocol) ExistsUuidForPublicKey(publicKeyPEM []byte) (bool, error) {
	publicKeyBytes, err := p.PublicKeyPEMToBytes(publicKeyPEM)
	if err != nil {
		return false, err
	}
	return p.ctxManager.ExistsUuidForPublicKey(publicKeyBytes)
}

func (p *Protocol) GetUuidForPublicKey(publicKeyPEM []byte) (uuid.UUID, error) {
	publicKeyBytes, err := p.PublicKeyPEMToBytes(publicKeyPEM)
	if err != nil {
		return uuid.Nil, err
	}
	return p.ctxManager.GetUuidForPublicKey(publicKeyBytes)
}

func (p *Protocol) ExistsSKID(uid uuid.UUID) bool {
	p.skidStoreMutex.RLock()
	defer p.skidStoreMutex.RUnlock()

	_, exists := p.skidStore[uid]
	return exists
}

func (p *Protocol) SetSKID(uid uuid.UUID, skid []byte) error {
	if len(skid) != SkidLen {
		return fmt.Errorf("invalid SKID length: expected %d, got %d", SkidLen, len(skid))
	}

	p.skidStoreMutex.Lock()
	p.skidStore[uid] = skid
	p.skidStoreMutex.Unlock()

	return nil
}

func (p *Protocol) GetSKID(uid uuid.UUID) ([]byte, error) {
	p.skidStoreMutex.RLock()
	skid, exists := p.skidStore[uid]
	p.skidStoreMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("SKID unknown for identity %s (missing X.509 public key certificate)", uid)
	}

	return skid, nil
}

func (p *Protocol) loadSKIDs() {
	certs, err := p.RequestCertificates()
	if err != nil {
		log.Error(err)
		return
	}

	var loadedSKIDs int

	for _, cert := range certs {
		kid := base64.StdEncoding.EncodeToString(cert.Kid)

		// get public key from certificate
		certificate, err := x509.ParseCertificate(cert.RawData)
		if err != nil {
			log.Errorf("%s: %v", kid, err)
			continue
		}

		pubKeyPEM, err := p.Crypto.EncodePublicKey(certificate.PublicKey)
		if err != nil {
			log.Debugf("%s: unable to encode public key: %v", kid, err)
			continue
		}

		// look up matching UUID for public key
		exists, err := p.ExistsUuidForPublicKey(pubKeyPEM)
		if err != nil {
			log.Errorf("%s: %v", kid, err)
			continue
		}
		if !exists {
			log.Debugf("%s: public key not found", kid)
			continue
		}
		log.Debugf("%s: public key found", kid)

		uid, err := p.GetUuidForPublicKey(pubKeyPEM)
		if err != nil {
			log.Errorf("%s: %v", kid, err)
			continue
		}

		// store KID
		err = p.SetSKID(uid, cert.Kid)
		if err != nil {
			log.Errorf("%s: %v", kid, err)
			continue
		}

		loadedSKIDs += 1
	}

	skids, _ := json.Marshal(p.skidStore)
	log.Infof("loaded %d matching certificates from server: %s", loadedSKIDs, skids)
}
