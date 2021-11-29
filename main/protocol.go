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
	"github.com/ubirch/ubirch-cose-client-go/main/config"

	log "github.com/sirupsen/logrus"
	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
)

const (
	SkidLen = 8
)

type Protocol struct {
	StorageManager
	pwHasher  *pw.Argon2idKeyDerivator
	authCache *sync.Map // {<uid>: <auth>}
	uidCache  *sync.Map // {<pub>: <uuid>}
}

func NewProtocol(storageManager StorageManager, conf *config.Config) *Protocol {
	argon2idParams := pw.GetArgon2idParams(conf.KdParamMemMiB, conf.KdParamTime, conf.KdParamParallelism,
		conf.KdParamKeyLen, conf.KdParamSaltLen)
	params, _ := json.Marshal(argon2idParams)
	log.Debugf("initialize argon2id key derivation with parameters %s", params)
	if conf.KdMaxTotalMemMiB != 0 {
		log.Debugf("max. total memory to use for key derivation at a time: %d MiB", conf.KdMaxTotalMemMiB)
	}
	if conf.KdUpdateParams {
		log.Debugf("key derivation parameter update for already existing password hashes enabled")
	}

	return &Protocol{
		StorageManager: storageManager,
		pwHasher:       pw.NewArgon2idKeyDerivator(conf.KdMaxTotalMemMiB, argon2idParams, conf.KdUpdateParams),
		authCache:      &sync.Map{},
		uidCache:       &sync.Map{},
	}
}

func (p *Protocol) StoreIdentity(tx TransactionCtx, i Identity) error {
	err := checkIdentityAttributesNotNil(&i)
	if err != nil {
		return err
	}

	// hash auth token
	i.Auth, err = p.pwHasher.GeneratePasswordHash(context.Background(), i.Auth)
	if err != nil {
		return fmt.Errorf("generating password hash failed: %v", err)
	}

	return p.StorageManager.StoreIdentity(tx, i)
}

func (p *Protocol) LoadIdentity(uid uuid.UUID) (i *Identity, err error) {
	i, err = p.StorageManager.LoadIdentity(uid)
	if err != nil {
		return nil, err
	}

	err = checkIdentityAttributesNotNil(i)
	if err != nil {
		return nil, err
	}

	return i, nil
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
	_, err = p.LoadIdentity(uid)
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

	i, err := p.LoadIdentity(uid)
	if err == ErrNotExist {
		return ok, found, nil
	}
	if err != nil {
		return ok, found, err
	}

	found = true

	needsUpdate, ok, err := p.pwHasher.CheckPassword(ctx, i.Auth, authToCheck)
	if err != nil || !ok {
		return ok, found, err
	}

	// auth check was successful
	p.authCache.Store(uid, authToCheck)

	if needsUpdate {
		if err := p.updatePwHash(uid, authToCheck); err != nil {
			log.Errorf("%s: password hash update failed: %v", uid, err)
		}
	}

	return ok, found, err
}

func (p *Protocol) updatePwHash(uid uuid.UUID, authToCheck string) error {
	log.Infof("%s: updating password hash", uid)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		return fmt.Errorf("could not initialize transaction: %v", err)
	}

	_, err = p.StorageManager.LoadAuthForUpdate(tx, uid)
	if err != nil {
		return fmt.Errorf("could not aquire lock for update: %v", err)
	}

	updatedHash, err := p.pwHasher.GeneratePasswordHash(ctx, authToCheck)
	if err != nil {
		return fmt.Errorf("could not generate new password hash: %v", err)
	}

	err = p.StorageManager.StoreAuth(tx, uid, updatedHash)
	if err != nil {
		return fmt.Errorf("could not store updated password hash: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("could not commit transaction after storing updated password hash: %v", err)
	}

	return nil
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
