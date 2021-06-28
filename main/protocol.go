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
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/encrypters"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const (
	SkidLen           = 8
	maxDbConnAttempts = 5
)

type Protocol struct {
	ubirch.Crypto
	ctxManager   ContextManager
	keyEncrypter *encrypters.KeyEncrypter

	identityCache *sync.Map // {<uid>: <*identity>}
	uidCache      *sync.Map // {<pub>: <uid>}
}

// Ensure Protocol implements the ContextManager interface
var _ ContextManager = (*Protocol)(nil)

func NewProtocol(ctxManager ContextManager, secret []byte) (*Protocol, error) {
	crypto := &ubirch.ECDSACryptoContext{}

	enc, err := encrypters.NewKeyEncrypter(secret, crypto)
	if err != nil {
		return nil, err
	}

	p := &Protocol{
		Crypto:       crypto,
		ctxManager:   ctxManager,
		keyEncrypter: enc,

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
	}

	return p, nil
}

func (p *Protocol) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	for i := 0; i < maxDbConnAttempts; i++ {
		transactionCtx, err = p.ctxManager.StartTransaction(ctx)
		if err != nil && isConnectionNotAvailable(err) {
			log.Debugf("StartTransaction connectionNotAvailable (%d of %d): %s", i+1, maxDbConnAttempts, err.Error())
			continue
		}
		break
	}

	return transactionCtx, err
}

func (p *Protocol) CloseTransaction(tx interface{}, commit bool) error {
	return p.ctxManager.CloseTransaction(tx, commit)
}

func (p *Protocol) StoreNewIdentity(tx interface{}, id Identity) error {
	err := p.checkIdentityAttributesNotNil(id)
	if err != nil {
		return err
	}

	// encrypt private key
	id.PrivateKey, err = p.keyEncrypter.Encrypt(id.PrivateKey)
	if err != nil {
		return err
	}

	// store public key raw bytes
	id.PublicKey, err = p.PublicKeyPEMToBytes(id.PublicKey)
	if err != nil {
		return err
	}

	return p.ctxManager.StoreNewIdentity(tx, id)
}

func (p *Protocol) GetIdentity(uid uuid.UUID) (id Identity, err error) {
	_id, found := p.identityCache.Load(uid)

	if found {
		id, found = _id.(Identity)
	}

	if !found {
		id, err = p.fetchIdentityFromStorage(uid)
		if err != nil {
			return id, err
		}

		p.identityCache.Store(uid, id)
	}

	return id, nil
}

func (p *Protocol) fetchIdentityFromStorage(uid uuid.UUID) (id Identity, err error) {
	for i := 0; i < maxDbConnAttempts; i++ {
		id, err = p.ctxManager.GetIdentity(uid)
		if err != nil && isConnectionNotAvailable(err) {
			log.Debugf("GetIdentity connectionNotAvailable (%d of %d): %s", i+1, maxDbConnAttempts, err.Error())
			continue
		}
		break
	}
	if err != nil {
		return id, err
	}

	id.PrivateKey, err = p.keyEncrypter.Decrypt(id.PrivateKey)
	if err != nil {
		return id, err
	}

	id.PublicKey, err = p.PublicKeyBytesToPEM(id.PublicKey)
	if err != nil {
		return id, err
	}

	err = p.checkIdentityAttributesNotNil(id)
	if err != nil {
		return id, err
	}

	return id, nil
}

func (p *Protocol) GetUuidForPublicKey(publicKeyPEM []byte) (uid uuid.UUID, err error) {
	publicKeyBytes, err := p.PublicKeyPEMToBytes(publicKeyPEM)
	if err != nil {
		return uuid.Nil, err
	}

	publicKeyBytesBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	_uid, found := p.uidCache.Load(publicKeyBytesBase64)

	if found {
		uid, found = _uid.(uuid.UUID)
	}

	if !found {
		uid, err = p.fetchUuidForPublicKeyFromStorage(publicKeyBytes)
		if err != nil {
			return uuid.Nil, err
		}

		p.uidCache.Store(publicKeyBytesBase64, uid)
	}

	return uid, nil
}

func (p *Protocol) fetchUuidForPublicKeyFromStorage(publicKeyBytes []byte) (uid uuid.UUID, err error) {
	for i := 0; i < maxDbConnAttempts; i++ {
		uid, err = p.ctxManager.GetUuidForPublicKey(publicKeyBytes)
		if err != nil && isConnectionNotAvailable(err) {
			log.Debugf("GetUuidForPublicKey connectionNotAvailable (%d of %d): %s", i+1, maxDbConnAttempts, err.Error())
			continue
		}
		break
	}
	return uid, err
}

func (p *Protocol) Exists(uid uuid.UUID) (exists bool, err error) {
	_, err = p.GetIdentity(uid)
	if err == ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (p *Protocol) checkIdentityAttributesNotNil(i Identity) error {
	if i.Uid == uuid.Nil {
		return fmt.Errorf("uuid has Nil value: %s", i.Uid)
	}

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

func (p *Protocol) Close() {}
