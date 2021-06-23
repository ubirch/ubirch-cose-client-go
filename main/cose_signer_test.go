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
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"net/http"
	"testing"
)

var (
	uid    = uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")
	key, _ = base64.StdEncoding.DecodeString("YUm0Xy475i7gnGNSnNJUriHQm33Uf+b/XHqZwjFluwM=")

	payloadJSON = "{\"test\": \"hello\"}"
)

func TestCoseSigner(t *testing.T) {
	c, privateKeyPEM := setupCryptoCtx(t)

	coseSigner, err := NewCoseSigner(c.SignHash, pseudoGetSKID)
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

	coseBytes, err := coseSigner.createSignedCOSE(hash, privateKeyPEM, uid[:], payloadCBOR)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("signed COSE [CBOR]: %x", coseBytes)
}

func TestCoseSign(t *testing.T) {
	c, privateKeyPEM := setupCryptoCtx(t)

	coseSigner, err := NewCoseSigner(c.SignHash, pseudoGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	msg := HTTPRequest{
		ID:      uid,
		Hash:    sha256.Sum256([]byte("test")),
		Payload: []byte("test"),
	}

	resp := coseSigner.Sign(msg, privateKeyPEM)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("response status code: %d", resp.StatusCode)
	}

	if resp.Content == nil {
		t.Errorf("empty response content")
	}
}

func TestCoseSignBadSkid(t *testing.T) {
	c, privateKeyPEM := setupCryptoCtx(t)

	coseSigner, err := NewCoseSigner(c.SignHash, pseudoGetSKIDReturnsErr)
	if err != nil {
		t.Fatal(err)
	}

	msg := HTTPRequest{
		ID:      uid,
		Hash:    sha256.Sum256([]byte("test")),
		Payload: []byte("test"),
	}

	resp := coseSigner.Sign(msg, privateKeyPEM)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("response status code: %d", resp.StatusCode)
	}

	if resp.Content == nil {
		t.Errorf("empty response content")
	}
}

func TestCoseSignBadKey(t *testing.T) {
	c, _ := setupCryptoCtx(t)

	coseSigner, err := NewCoseSigner(c.SignHash, pseudoGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	msg := HTTPRequest{
		ID:      uid,
		Hash:    sha256.Sum256([]byte("test")),
		Payload: []byte("test"),
	}

	resp := coseSigner.Sign(msg, nil)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("response status code: %d", resp.StatusCode)
	}

	if resp.Content == nil {
		t.Errorf("empty response content")
	}
}

func TestCoseSignBadSignature(t *testing.T) {
	coseSigner, err := NewCoseSigner(pseudoSignReturnsNilSignature, pseudoGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	msg := HTTPRequest{
		ID:      uid,
		Hash:    sha256.Sum256([]byte("test")),
		Payload: []byte("test"),
	}

	resp := coseSigner.Sign(msg, nil)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("response status code: %d", resp.StatusCode)
	}

	if resp.Content == nil {
		t.Errorf("empty response content")
	}
}

func TestCoseBadGetCBORFromJSON(t *testing.T) {
	c, _ := setupCryptoCtx(t)

	coseSigner, err := NewCoseSigner(c.SignHash, pseudoGetSKIDReturnsErr)
	if err != nil {
		t.Fatal(err)
	}

	_, err = coseSigner.GetCBORFromJSON(nil)
	if err == nil {
		t.Errorf("GetCBORFromJSON(nil) returned no error")
	}
}

func setupCryptoCtx(t *testing.T) (cryptoCtx ubirch.Crypto, privKeyPEM []byte) {
	cryptoCtx = &ubirch.ECDSACryptoContext{}

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

	return cryptoCtx, privKeyPEM
}

func pseudoGetSKID(uid uuid.UUID) ([]byte, error) {
	return base64.StdEncoding.DecodeString("6ZaL9M6NcG0=")
}

func pseudoGetSKIDReturnsErr(uid uuid.UUID) ([]byte, error) {
	return nil, fmt.Errorf("test error")
}

func pseudoSignReturnsNilSignature(privKeyPEM []byte, hash []byte) ([]byte, error) {
	return nil, nil
}
