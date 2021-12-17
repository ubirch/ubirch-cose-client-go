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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
)

var (
	payloadJSON = "{\"test\": \"hello\"}"
)

func TestCoseSigner(t *testing.T) {
	c := setupCryptoCtx(t, testUuid)

	pubKeyBytes, err := c.GetPublicKeyBytes(testUuid)
	require.NoError(t, err)
	t.Logf("public key: %x", pubKeyBytes)

	coseSigner, err := NewCoseSigner(c.SignHash, mockGetSKID)
	require.NoError(t, err)

	t.Logf("payload [JSON]: %s", payloadJSON)

	payloadCBOR, err := coseSigner.GetCBORFromJSON([]byte(payloadJSON))
	require.NoError(t, err)

	t.Logf("payload [CBOR]: %x", payloadCBOR)

	toBeSigned, err := coseSigner.GetSigStructBytes(payloadCBOR)
	require.NoError(t, err)

	t.Logf("Sig_structure [CBOR]: %x", toBeSigned)

	hash := sha256.Sum256(toBeSigned)

	t.Logf("sha256 hash [base64]: %s", base64.StdEncoding.EncodeToString(hash[:]))

	ctx := context.Background()

	coseBytes, err := coseSigner.createSignedCOSE(ctx, testUuid, hash, testUuid[:], payloadCBOR)
	require.NoError(t, err)

	t.Logf("signed COSE [CBOR]: %x", coseBytes)
}

func TestCoseSign(t *testing.T) {
	c := setupCryptoCtx(t, testUuid)

	coseSigner, err := NewCoseSigner(c.SignHash, mockGetSKID)
	require.NoError(t, err)

	msg := h.HTTPRequest{
		ID:      testUuid,
		Hash:    sha256.Sum256([]byte("test")),
		Payload: []byte("test"),
	}

	resp := coseSigner.Sign(msg)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("response status code: %d", resp.StatusCode)
	}

	if resp.Content == nil {
		t.Errorf("empty response content")
	}
}

func TestCoseSignBadGetSKID(t *testing.T) {

	testCases := []struct {
		name       string
		getSKID    GetSKID
		StatusCode int
		Content    []byte
	}{
		{
			name: "ErrCertServerNotAvailable",
			getSKID: func(uid uuid.UUID) ([]byte, error) {
				return nil, ErrCertServerNotAvailable
			},
			StatusCode: http.StatusServiceUnavailable,
			Content:    []byte(ErrCertServerNotAvailable.Error()),
		},
		{
			name: "ErrCertNotFound",
			getSKID: func(uid uuid.UUID) ([]byte, error) {
				return nil, ErrCertNotFound
			},
			StatusCode: http.StatusNotFound,
			Content:    []byte(ErrCertNotFound.Error()),
		},
		{
			name: "ErrCertExpired",
			getSKID: func(uid uuid.UUID) ([]byte, error) {
				return nil, ErrCertExpired
			},
			StatusCode: http.StatusInternalServerError,
			Content:    []byte(ErrCertExpired.Error()),
		},
		{
			name: "ErrCertNotYetValid",
			getSKID: func(uid uuid.UUID) ([]byte, error) {
				return nil, ErrCertNotYetValid
			},
			StatusCode: http.StatusTooEarly,
			Content:    []byte(ErrCertNotYetValid.Error()),
		},
		{
			name: "unexpected error",
			getSKID: func(uid uuid.UUID) ([]byte, error) {
				return nil, testError
			},
			StatusCode: http.StatusInternalServerError,
			Content:    []byte(testError.Error()),
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			coseSigner, err := NewCoseSigner(mockSign, c.getSKID)
			require.NoError(t, err)

			msg := h.HTTPRequest{
				ID:      testUuid,
				Hash:    sha256.Sum256([]byte("test")),
				Payload: []byte("test"),
			}

			resp := coseSigner.Sign(msg)

			assert.Equal(t, c.StatusCode, resp.StatusCode)
			assert.Equal(t, c.Content, resp.Content)
		})
	}
}

func TestCoseSignBadContext(t *testing.T) {
	c := setupCryptoCtx(t, testUuid)

	coseSigner, err := NewCoseSigner(c.SignHash, mockGetSKID)
	require.NoError(t, err)

	err = coseSigner.signSem.Acquire(context.Background(), 1)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	msg := h.HTTPRequest{
		ID:      testUuid,
		Hash:    sha256.Sum256([]byte("test")),
		Payload: []byte("test"),
		Ctx:     ctx,
	}

	_, err = coseSigner.createSignedCOSE(msg.Ctx, msg.ID, msg.Hash, testSKID, msg.Payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire semaphore for signing")
}

func TestCoseSignBadSign(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSignReturnsError, mockGetSKID)
	require.NoError(t, err)

	msg := h.HTTPRequest{
		ID:      testUuid,
		Hash:    sha256.Sum256([]byte("test")),
		Payload: []byte("test"),
	}

	resp := coseSigner.Sign(msg)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("response status code: %d", resp.StatusCode)
	}

	if resp.Content == nil {
		t.Errorf("empty response content")
	}
}

func TestCoseSignBadSignature(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSignReturnsNilSignature, mockGetSKID)
	require.NoError(t, err)

	msg := h.HTTPRequest{
		ID:      testUuid,
		Hash:    sha256.Sum256([]byte("test")),
		Payload: []byte("test"),
	}

	resp := coseSigner.Sign(msg)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("response status code: %d", resp.StatusCode)
	}

	if resp.Content == nil {
		t.Errorf("empty response content")
	}
}

func TestCoseSigner_GetSigStructBytes(t *testing.T) {
	coseSigner := CoseSigner{}
	_, err := coseSigner.GetSigStructBytes([]byte(""))
	assert.EqualError(t, err, "empty payload")
}

func TestCoseBadGetCBORFromJSON(t *testing.T) {
	c := setupCryptoCtx(t, testUuid)

	coseSigner, err := NewCoseSigner(c.SignHash, mockGetSKID)
	require.NoError(t, err)

	_, err = coseSigner.GetCBORFromJSON(nil)
	assert.Error(t, err)
}

func setupCryptoCtx(t *testing.T, uid uuid.UUID) (cryptoCtx ubirch.Crypto) {
	cryptoCtx = &ubirch.ECDSACryptoContext{
		Keystore: &MockKeystorer{},
	}

	err := cryptoCtx.SetKey(uid, testKey)
	require.NoError(t, err)

	return cryptoCtx
}

func mockGetSKID(uuid.UUID) ([]byte, error) {
	return base64.StdEncoding.DecodeString("6ZaL9M6NcG0=")
}

func mockSign(uuid.UUID, []byte) ([]byte, error) {
	return make([]byte, 64), nil
}

func mockSignReturnsError(uuid.UUID, []byte) ([]byte, error) {
	return nil, testError
}

func mockSignReturnsNilSignature(uuid.UUID, []byte) ([]byte, error) {
	return nil, nil
}
