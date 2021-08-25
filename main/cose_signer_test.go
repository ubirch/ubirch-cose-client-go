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
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

var (
	testKey, _ = base64.StdEncoding.DecodeString("YUm0Xy475i7gnGNSnNJUriHQm33Uf+b/XHqZwjFluwM=")

	payloadJSON = "{\"test\": \"hello\"}"
)

func TestCoseSigner(t *testing.T) {
	c, privKeyPEM := setupCryptoCtx(t)

	pubKeyPEM, err := c.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyBytes, err := c.PublicKeyPEMToBytes(pubKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("public key: %x", pubKeyBytes)

	coseSigner, err := NewCoseSigner(c.SignHash, mockGetSKID)
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

	coseBytes, err := coseSigner.createSignedCOSE(hash, privKeyPEM, test.Uuid[:], payloadCBOR)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("signed COSE [CBOR]: %x", coseBytes)
}

func TestCoseSign(t *testing.T) {
	c, privKeyPEM := setupCryptoCtx(t)

	coseSigner, err := NewCoseSigner(c.SignHash, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	msg := HTTPRequest{
		ID:      test.Uuid,
		Hash:    sha256.Sum256([]byte("test")),
		Payload: []byte("test"),
	}

	resp := coseSigner.Sign(msg, privKeyPEM)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("response status code: %d", resp.StatusCode)
	}

	if resp.Content == nil {
		t.Errorf("empty response content")
	}
}

func TestCoseSignBadSkid(t *testing.T) {
	c, privateKeyPEM := setupCryptoCtx(t)

	coseSigner, err := NewCoseSigner(c.SignHash, mockGetSKIDReturnsErr)
	if err != nil {
		t.Fatal(err)
	}

	msg := HTTPRequest{
		ID:      test.Uuid,
		Hash:    sha256.Sum256([]byte("test")),
		Payload: []byte("test"),
	}

	resp := coseSigner.Sign(msg, privateKeyPEM)

	if resp.StatusCode != http.StatusTooEarly {
		t.Errorf("response status code: %d", resp.StatusCode)
	}

	if resp.Content == nil {
		t.Errorf("empty response content")
	}
}

func TestCoseSignBadKey(t *testing.T) {
	c, _ := setupCryptoCtx(t)

	coseSigner, err := NewCoseSigner(c.SignHash, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	msg := HTTPRequest{
		ID:      test.Uuid,
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
	coseSigner, err := NewCoseSigner(mockSignReturnsNilSignature, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	msg := HTTPRequest{
		ID:      test.Uuid,
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

	coseSigner, err := NewCoseSigner(c.SignHash, mockGetSKIDReturnsErr)
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

	privKeyPEM, err := cryptoCtx.PrivateKeyBytesToPEM(testKey)
	if err != nil {
		t.Fatal(err)
	}

	return cryptoCtx, privKeyPEM
}

func mockGetSKID(uuid.UUID) ([]byte, error) {
	return base64.StdEncoding.DecodeString("6ZaL9M6NcG0=")
}

func mockGetSKIDReturnsErr(uuid.UUID) ([]byte, error) {
	return nil, test.Error
}

func mockSign([]byte, []byte) ([]byte, error) {
	return make([]byte, 64), nil
}

func mockSignReturnsNilSignature([]byte, []byte) ([]byte, error) {
	return nil, nil
}
