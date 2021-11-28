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
	SkidLen = 8
)

type Protocol struct {
	StorageManager

	pwHasher       *pw.Argon2idKeyDerivator
	pwHasherParams *pw.Argon2idParams

	authCache *sync.Map // {<uid>: <auth>}
	uidCache  *sync.Map // {<pub>: <uid>}
}

func NewProtocol(storageManager StorageManager, conf *Config) *Protocol {
	argon2idParams := pw.GetArgon2idParams(conf.KdParamMemMiB, conf.KdParamTime, conf.KdParamParallelism,
		conf.KdParamKeyLen, conf.KdParamSaltLen)
	params, _ := json.Marshal(argon2idParams)
	log.Debugf("initialize argon2id key derivation with parameters %s", params)

	return &Protocol{
		StorageManager: storageManager,

		pwHasher:       pw.NewArgon2idKeyDerivator(conf.KdMaxTotalMemMiB),
		pwHasherParams: argon2idParams,

		authCache: &sync.Map{},
		uidCache:  &sync.Map{},
	}
}

func (p *Protocol) StoreNewIdentity(transactionCtx interface{}, id Identity) error {
	err := checkIdentityAttributesNotNil(&id)
	if err != nil {
		return err
	}

	// hash auth token
	id.Auth, err = p.pwHasher.GeneratePasswordHash(context.Background(), id.Auth, p.pwHasherParams)
	if err != nil {
		return fmt.Errorf("generating password hash failed: %v", err)
	}

	return p.StorageManager.StoreNewIdentity(transactionCtx, id)
}

func (p *Protocol) GetIdentity(uid uuid.UUID) (id Identity, err error) {
	id, err = p.StorageManager.GetIdentity(uid)
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
		uid, err = p.StorageManager.GetUuidForPublicKey(publicKeyPEM)
		if err != nil {
			return uuid.Nil, err
		}

		p.uidCache.Store(pubKeyID, uid)
	}

	return uid, nil
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

func (p *Protocol) CheckAuth(ctx context.Context, uid uuid.UUID, authToCheck string) (ok, found bool, err error) {
	_auth, found := p.authCache.Load(uid)

	if found {
		if auth, ok := _auth.(string); ok {
			return auth == authToCheck, found, err
		}
	}

	i, err := p.GetIdentity(uid)
	if err == ErrNotExist {
		return ok, found, nil
	}
	if err != nil {
		return ok, found, err
	}

	found = true

	ok, err = p.pwHasher.CheckPassword(ctx, i.Auth, authToCheck)
	if err != nil || !ok {
		return ok, found, err
	}

	// auth check was successful
	p.authCache.Store(uid, authToCheck)

	return ok, found, err
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
