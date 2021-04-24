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

type ExtendedProtocol struct {
	ubirch.Protocol
	ContextManager
}

func NewExtendedProtocol(cryptoCtx ubirch.Crypto, ctxManager ContextManager) (*ExtendedProtocol, error) {
	p := &ExtendedProtocol{
		Protocol: ubirch.Protocol{
			Crypto: cryptoCtx,
		},
		ContextManager: ctxManager,
	}

	return p, nil
}

func (p *ExtendedProtocol) GetPrivateKey(uid uuid.UUID) (privKeyPEM []byte, err error) {
	// todo sanity checks
	return p.ContextManager.GetPrivateKey(uid)
}
func (p *ExtendedProtocol) SetPrivateKey(uid uuid.UUID, privKeyPEM []byte) error {
	// todo sanity checks
	return p.ContextManager.SetPrivateKey(uid, privKeyPEM)
}

func (p *ExtendedProtocol) GetPublicKey(uid uuid.UUID) (pubKeyPEM []byte, err error) {
	// todo sanity checks
	return p.ContextManager.GetPublicKey(uid)

}
func (p *ExtendedProtocol) SetPublicKey(uid uuid.UUID, pubKeyPEM []byte) error {
	// todo sanity checks
	return p.ContextManager.SetPublicKey(uid, pubKeyPEM)
}
