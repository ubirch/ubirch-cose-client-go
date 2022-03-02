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
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"github.com/ubirch/ubirch-cose-client-go/main/encryption"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

const (
	SkidLen = 8
)

type Protocol struct {
	StorageManager

	Crypto       ubirch.Crypto
	keyEncrypter *encrypters.PKCS8KeyEncrypter
	keyCache     *KeyCache

	authCache *sync.Map // {<uid>: <auth>}
	uuidCache *sync.Map // {<pub>: <uuid>}
}

func NewProtocol(storageManager StorageManager, conf *config.Config) (*Protocol, error) {
	if storageManager == nil {
		return nil, fmt.Errorf("storageManager can not be nil")
	}

	keyCache := NewKeyCache()

	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: keyCache,
	}

	enc, err := encrypters.NewPKCS8KeyEncrypter(conf.SecretBytes, cryptoCtx)
	if err != nil {
		return nil, err
	}

	return &Protocol{
		StorageManager: storageManager,

		Crypto:       cryptoCtx,
		keyEncrypter: enc,
		keyCache:     keyCache,

		authCache: &sync.Map{},
		uuidCache: &sync.Map{},
	}, nil
}

func (p *Protocol) StoreIdentity(tx TransactionCtx, i Identity) error {
	err := checkIdentityAttributesNotNil(&i)
	if err != nil {
		return err
	}

	// encrypt private key
	i.PrivateKey, err = p.keyEncrypter.Encrypt(i.PrivateKey)
	if err != nil {
		return err
	}

	// store public key raw bytes
	i.PublicKey, err = p.Crypto.PublicKeyPEMToBytes(i.PublicKey)
	if err != nil {
		return err
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

	// load caches
	i.PrivateKey, err = p.keyEncrypter.Decrypt(i.PrivateKey)
	if err != nil {
		return nil, err
	}

	err = p.keyCache.SetPrivateKey(uid, i.PrivateKey)
	if err != nil {
		return nil, err
	}

	i.PublicKey, err = p.Crypto.PublicKeyBytesToPEM(i.PublicKey)
	if err != nil {
		return nil, err
	}

	err = p.keyCache.SetPublicKey(uid, i.PublicKey)
	if err != nil {
		return nil, err
	}

	return i, nil
}

func (p *Protocol) GetUuidForPublicKey(publicKeyPEM []byte) (uid uuid.UUID, err error) {
	pubKeyID := getPubKeyID(publicKeyPEM)

	_uid, found := p.uuidCache.Load(pubKeyID)

	if found {
		uid, found = _uid.(uuid.UUID)
	}

	if !found {
		publicKeyBytes, err := p.Crypto.PublicKeyPEMToBytes(publicKeyPEM)
		if err != nil {
			return uuid.Nil, err
		}

		uid, err = p.StorageManager.GetUuidForPublicKey(publicKeyBytes)
		if err != nil {
			return uuid.Nil, err
		}

		p.uuidCache.Store(pubKeyID, uid)
	}

	return uid, nil
}

func (p *Protocol) LoadPrivateKey(uid uuid.UUID) (privKeyPEM []byte, err error) {
	privKeyPEM, err = p.keyCache.GetPrivateKey(uid)
	if err != nil {
		i, err := p.LoadIdentity(uid)
		if err != nil {
			return nil, err
		}

		privKeyPEM = i.PrivateKey
	}

	return privKeyPEM, nil
}

func (p *Protocol) LoadPublicKey(uid uuid.UUID) (pubKeyPEM []byte, err error) {
	pubKeyPEM, err = p.keyCache.GetPublicKey(uid)
	if err != nil {
		i, err := p.LoadIdentity(uid)
		if err != nil {
			return nil, err
		}

		pubKeyPEM = i.PublicKey
	}

	return pubKeyPEM, nil
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

func (p *Protocol) CheckAuth(uid uuid.UUID, authToCheck string) (ok, found bool, err error) {
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

	ok = i.Auth == authToCheck
	if !ok {
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

	if len(i.PrivateKey) == 0 {
		return fmt.Errorf("empty private key")
	}

	if len(i.PublicKey) == 0 {
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
