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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
)

const (
	SkidLen             = 8
	maxRecoveryAttempts = 2
)

type Protocol struct {
	StorageManager

	PwHasher       *pw.Argon2idKeyDerivator
	PwHasherParams *pw.Argon2idParams

	identityCache *sync.Map // {<uid>: <*identity>}
	uidCache      *sync.Map // {<pub>: <uid>}
}

// Ensure Protocol implements the StorageManager interface
var _ StorageManager = (*Protocol)(nil)

func NewProtocol(storageManager StorageManager, conf *Config) *Protocol {
	argon2idParams := pw.GetArgon2idParams(conf.KdParamMemMiB, conf.KdParamTime, conf.KdParamParallelism)
	params, _ := json.Marshal(argon2idParams)
	log.Debugf("initialize argon2id key derivation with parameters %s", params)

	return &Protocol{
		StorageManager: storageManager,

		PwHasher:       pw.NewArgon2idKeyDerivator(conf.KdMaxTotalMemMiB),
		PwHasherParams: argon2idParams,

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
	}
}

func (p *Protocol) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	for i := 0; i <= maxRecoveryAttempts; i++ {
		transactionCtx, err = p.StorageManager.StartTransaction(ctx)
		if err != nil && p.StorageManager.IsRecoverable(err) {
			log.Warnf("StartTransaction error: %v: isRecoverable (%d / %d)", err, i, maxRecoveryAttempts)
			continue
		}
		break
	}
	return transactionCtx, err
}

func (p *Protocol) StoreNewIdentity(transactionCtx interface{}, id Identity) error {
	err := checkIdentityAttributesNotNil(&id)
	if err != nil {
		return err
	}

	for i := 0; i <= maxRecoveryAttempts; i++ {
		err = p.StorageManager.StoreNewIdentity(transactionCtx, id)
		if err != nil && p.StorageManager.IsRecoverable(err) {
			log.Warnf("StoreNewIdentity error: %v: isRecoverable (%d / %d)", err, i, maxRecoveryAttempts)
			continue
		}
		break
	}
	return err
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
	for i := 0; i <= maxRecoveryAttempts; i++ {
		id, err = p.StorageManager.GetIdentity(uid)
		if err != nil && p.StorageManager.IsRecoverable(err) {
			log.Warnf("GetIdentity error: %v: isRecoverable (%d / %d)", err, i, maxRecoveryAttempts)
			continue
		}
		break
	}
	if err != nil {
		return id, err
	}

	err = checkIdentityAttributesNotNil(&id)
	if err != nil {
		return id, err
	}

	return id, nil
}

func (p *Protocol) GetUuidForPublicKey(publicKeyPEM []byte) (uid uuid.UUID, err error) {
	pubKeyID := getPubKeyID(publicKeyPEM)

	_uid, found := p.uidCache.Load(pubKeyID)

	if found {
		uid, found = _uid.(uuid.UUID)
	}

	if !found {
		uid, err = p.fetchUuidForPublicKeyFromStorage(publicKeyPEM)
		if err != nil {
			return uuid.Nil, err
		}

		p.uidCache.Store(pubKeyID, uid)
	}

	return uid, nil
}

func (p *Protocol) fetchUuidForPublicKeyFromStorage(publicKeyPEM []byte) (uid uuid.UUID, err error) {
	for i := 0; i <= maxRecoveryAttempts; i++ {
		uid, err = p.StorageManager.GetUuidForPublicKey(publicKeyPEM)
		if err != nil && p.StorageManager.IsRecoverable(err) {
			log.Warnf("GetUuidForPublicKey error: %v: isRecoverable (%d / %d)", err, i, maxRecoveryAttempts)
			continue
		}
		break
	}
	return uid, err
}

func (p *Protocol) IsInitialized(uid uuid.UUID) (initialized bool, err error) {
	_, err = p.GetIdentity(uid)
	if err == ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func checkIdentityAttributesNotNil(i *Identity) error {
	if i.Uid == uuid.Nil {
		return fmt.Errorf("uuid has Nil value: %s", i.Uid)
	}

	if len(i.PublicKeyPEM) == 0 {
		return fmt.Errorf("empty public key")
	}

	if len(i.Auth) == 0 {
		return fmt.Errorf("empty auth")
	}

	return nil
}

func getPubKeyID(publicKeyPEM []byte) string {
	sum256 := sha256.Sum256(publicKeyPEM)
	return base64.StdEncoding.EncodeToString(sum256[:])
}
