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
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type Protocol struct {
	ubirch.Crypto
	ContextManager
	*Client
	keyEncrypter *KeyEncrypter
}

func NewProtocol(ctxManager ContextManager, secret []byte, client *Client) (*Protocol, error) {
	crypto := &ubirch.ECDSACryptoContext{}

	enc, err := NewKeyEncrypter(secret, crypto)
	if err != nil {
		return nil, err
	}

	return &Protocol{
		Crypto:         crypto,
		ContextManager: ctxManager,
		Client:         client,
		keyEncrypter:   enc,
	}, nil
}

func (p *Protocol) SetPrivateKey(uid uuid.UUID, privateKeyPem []byte) error {
	encryptedPrivateKey, err := p.keyEncrypter.Encrypt(privateKeyPem)
	if err != nil {
		return err
	}

	return p.ContextManager.SetPrivateKey(uid, encryptedPrivateKey)
}

func (p *Protocol) GetPrivateKey(uid uuid.UUID) (privateKeyPem []byte, err error) {
	encryptedPrivateKey, err := p.ContextManager.GetPrivateKey(uid)
	if err != nil {
		return nil, err
	}

	return p.keyEncrypter.Decrypt(encryptedPrivateKey)
}
