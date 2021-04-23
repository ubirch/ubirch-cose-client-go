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
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"testing"
)

var (
	uid    = uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")
	key, _ = base64.StdEncoding.DecodeString("YUm0Xy475i7gnGNSnNJUriHQm33Uf+b/XHqZwjFluwM=")

	payloadJSON = "{\"test\": 123}"
)

func TestCoseSign(t *testing.T) {
	cryptoCtx := setupCrypto(t)

	coseSigner, err := NewCoseSigner(cryptoCtx)
	if err != nil {
		t.Fatal(err)
	}

	payloadCBOR, err := getCBORFromJSON(coseSigner, []byte(payloadJSON))
	if err != nil {
		t.Fatal(err)
	}

	toBeSigned, err := coseSigner.GetSigStructBytes(payloadCBOR)
	if err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256(toBeSigned)

	coseBytes, err := coseSigner.getSignedCOSE(uid, hash, payloadCBOR)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("signed COSE: %x", coseBytes)
}

func setupCrypto(t *testing.T) *ubirch.ECDSACryptoContext {
	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: ubirch.NewEncryptedKeystore([]byte("1234567890123456")),
	}

	err := cryptoCtx.SetKey(uid, key)
	if err != nil {
		t.Fatal(err)
	}

	pubKey, _ := cryptoCtx.GetPublicKey(uid)
	t.Logf("public key: %x", pubKey)

	return cryptoCtx
}

func getCBORFromJSON(encoder *CoseSigner, jsonData []byte) ([]byte, error) {
	var reqDump interface{}

	err := json.Unmarshal(jsonData, &reqDump)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON request body: %v", err)
	}

	return encoder.encMode.Marshal(reqDump)
}
