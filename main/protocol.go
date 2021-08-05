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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	//"runtime"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
)

const (
	SkidLen           = 8
	maxDbConnAttempts = 5
)

type Protocol struct {
	ubirch.Crypto
	ctxManager ContextManager

	pwHasher       pw.PasswordHasher
	pwHasherParams pw.PasswordHashingParams

	identityCache *sync.Map // {<uid>: <*identity>}
	uidCache      *sync.Map // {<pub>: <uid>}
}

// Ensure Protocol implements the ContextManager interface
var _ ContextManager = (*Protocol)(nil)

func NewProtocol(crypto ubirch.Crypto, ctxManager ContextManager, memMB uint32) *Protocol {
	kd := &pw.PseudoPWHasher{} // FIXME
	//kd := &pw.Argon2idKeyDerivator{}
	//p := &pw.Argon2idParams{
	//	Time:    1,
	//	Memory:  memMB * 1024,
	//	Threads: uint8(runtime.NumCPU() * 2), // 2 * number of cores
	//	KeyLen:  24,
	//}
	//kdParams, err := p.Encode()
	//if err != nil {
	//	log.Errorf("failed to encode argon2id key derivation parameter: %v", err)
	//}
	//log.Debugf("argon2id key derivation with parameters %s", kdParams)

	return &Protocol{
		Crypto:     crypto,
		ctxManager: ctxManager,

		pwHasher:       kd,
		pwHasherParams: kd.DefaultParams(), // FIXME
		//pwHasherParams: kdParams,

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
	}
}

func (p *Protocol) StoreNewIdentity(id Identity) error {
	err := checkIdentityAttributesNotNil(&id)
	if err != nil {
		return err
	}

	for i := 0; i < maxDbConnAttempts; i++ {
		err = p.ctxManager.StoreNewIdentity(id)
		if err != nil && isConnectionNotAvailable(err) {
			log.Debugf("StoreNewIdentity connectionNotAvailable (%d of %d): %s", i+1, maxDbConnAttempts, err.Error())
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

func (p *Protocol) isInitialized(uid uuid.UUID) (initialized bool, err error) {
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

	if len(i.PW.AlgoID) == 0 {
		return fmt.Errorf("empty password algoID")
	}

	if len(i.PW.Hash) == 0 {
		return fmt.Errorf("empty password hash")
	}

	if len(i.PW.Salt) == 0 {
		return fmt.Errorf("empty password salt")
	}

	if len(i.PW.Params) == 0 {
		return fmt.Errorf("empty password params")
	}

	return nil
}

func getPubKeyID(publicKeyPEM []byte) string {
	sum256 := sha256.Sum256(publicKeyPEM)
	return base64.StdEncoding.EncodeToString(sum256[:])
}

func (p *Protocol) Close() {}
