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
	p, privateKeyPEM := setupProtocol(t)

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

	signature, err := coseSigner.SignHash(privateKeyPEM, hash[:])
	if err != nil {
		t.Fatal(err)
	}

	coseBytes, err := coseSigner.getCOSE(uid[:], payloadCBOR, signature)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("signed COSE [CBOR]: %x", coseBytes)
}

func setupProtocol(t *testing.T) (protocol *Protocol, privKeyPEM []byte) {
	cryptoCtx := &ubirch.ECDSACryptoContext{}

	privKeyPEM, err := cryptoCtx.PrivateKeyBytesToPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := cryptoCtx.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyBytes, err := cryptoCtx.PublicKeyPEMToBytes(pubKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("public key: %x", pubKeyBytes)

	return &Protocol{
		Crypto: cryptoCtx,
	}, privKeyPEM
}
