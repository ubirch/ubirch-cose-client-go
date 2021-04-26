// Copyright (c) 2021 ubirch GmbH
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
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"testing"
)

var (
	uid    = uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")
	key, _ = base64.StdEncoding.DecodeString("YUm0Xy475i7gnGNSnNJUriHQm33Uf+b/XHqZwjFluwM=")

	payloadJSON = "{\"test\": \"hello\"}"
)

func TestCoseSign(t *testing.T) {
	p := setupProtocol(t)

	coseSigner, err := NewCoseSigner(p)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("payload [JSON]: %s", payloadJSON)

	payloadCBOR, err := coseSigner.GetCBORFromJSON([]byte(payloadJSON))
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("payload [CBOR]: %x", payloadCBOR)

	toBeSigned, err := coseSigner.GetSigStructBytes(payloadCBOR)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Sig_structure [CBOR]: %x", toBeSigned)

	hash := sha256.Sum256(toBeSigned)

	t.Logf("sha256 hash [base64]: %s", base64.StdEncoding.EncodeToString(hash[:]))

	coseBytes, err := coseSigner.getSignedCOSE(uid, hash, payloadCBOR)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("signed COSE [CBOR]: %x", coseBytes)
}

func setupProtocol(t *testing.T) *Protocol {
	cryptoCtx := &ubirch.ECDSACryptoContext{}

	privKeyPEM, err := cryptoCtx.PrivateKeyBytesToPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, _ := cryptoCtx.GetPublicKeyFromPrivateKey(privKeyPEM)
	pubKeyBytes, _ := cryptoCtx.PublicKeyPEMToBytes(pubKeyPEM)
	t.Logf("public key [base64]: %s", base64.StdEncoding.EncodeToString(pubKeyBytes))

	ctxManager := &testContextManager{
		privateKey: privKeyPEM,
		publicKey:  pubKeyPEM,
	}

	return &Protocol{
		Crypto:         cryptoCtx,
		ContextManager: ctxManager,
		Client:         &Client{},
	}
}

type testContextManager struct {
	privateKey []byte
	publicKey  []byte
}

func (t testContextManager) GetPrivateKey(uid uuid.UUID) (privKey []byte, err error) {
	return t.privateKey, nil
}

func (t testContextManager) GetPublicKey(uid uuid.UUID) (pubKey []byte, err error) {
	return t.publicKey, nil
}

func (t testContextManager) Exists(uid uuid.UUID) bool {
	panic("not implemented")
}

func (t testContextManager) SetPrivateKey(uid uuid.UUID, privKey []byte) error {
	panic("not implemented")
}

func (t testContextManager) SetPublicKey(uid uuid.UUID, pubKey []byte) error {
	panic("not implemented")
}

var _ ContextManager = (*testContextManager)(nil)
