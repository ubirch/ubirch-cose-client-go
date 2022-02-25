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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
)

var (
	payloadJSON   = "{\"test\": \"hello\"}"
	testSignature = []byte{0x52, 0xfd, 0xfc, 0x7, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0xf, 0x9a, 0x62, 0x1d, 0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x3, 0x7c, 0x4d, 0x7b, 0xbb, 0x4, 0x7, 0xd1, 0xe2, 0xc6, 0x49, 0x81, 0x85, 0x5a, 0xd8, 0x68, 0x1d, 0xd, 0x86, 0xd1, 0xe9, 0x1e, 0x0, 0x16, 0x79, 0x39, 0xcb, 0x66, 0x94, 0xd2, 0xc4, 0x22, 0xac, 0xd2, 0x8, 0xa0, 0x7, 0x29, 0x39, 0x48, 0x7f, 0x69, 0x99}
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

	msg := h.HTTPRequest{
		ID:      testUuid,
		Hash:    hash,
		Payload: payloadCBOR,
		Ctx:     context.Background(),
	}

	resp := coseSigner.Sign(msg)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	t.Logf("signed COSE [CBOR]: %x", resp.Content)

	// verify response
	respCoseObj := &COSE_Sign1{}
	dec := cbor.NewDecoder(bytes.NewReader(resp.Content))
	require.NoError(t, dec.Decode(respCoseObj))

	respSigStruct := &Sig_structure{
		Context:         "Signature1",
		ProtectedHeader: respCoseObj.Protected,
		External:        []byte{},
		Payload:         respCoseObj.Payload,
	}

	respToBeSigned, err := coseSigner.encMode.Marshal(respSigStruct)
	require.NoError(t, err)

	verified, err := c.Verify(msg.ID, respToBeSigned, respCoseObj.Signature)
	require.NoError(t, err)
	assert.True(t, verified)
}

func TestCoseSigner_Sign(t *testing.T) {

	testCases := []struct {
		name       string
		getSKID    GetSKID
		signHash   SignHash
		StatusCode int
		ErrHeader  string
		Content    []byte
	}{
		{
			name:       "happy path",
			getSKID:    mockGetSKID,
			signHash:   mockSign,
			StatusCode: http.StatusOK,
			ErrHeader:  "",
			Content:    []byte{0xd2, 0x84, 0x43, 0xa1, 0x1, 0x26, 0xa1, 0x4, 0x48, 0xa3, 0x78, 0xce, 0x33, 0x3d, 0xd4, 0xf7, 0x76, 0x44, 0x74, 0x65, 0x73, 0x74, 0x58, 0x40, 0x52, 0xfd, 0xfc, 0x7, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0xf, 0x9a, 0x62, 0x1d, 0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x3, 0x7c, 0x4d, 0x7b, 0xbb, 0x4, 0x7, 0xd1, 0xe2, 0xc6, 0x49, 0x81, 0x85, 0x5a, 0xd8, 0x68, 0x1d, 0xd, 0x86, 0xd1, 0xe9, 0x1e, 0x0, 0x16, 0x79, 0x39, 0xcb, 0x66, 0x94, 0xd2, 0xc4, 0x22, 0xac, 0xd2, 0x8, 0xa0, 0x7, 0x29, 0x39, 0x48, 0x7f, 0x69, 0x99},
		},
		{
			name: "getSKID ErrCertServerNotAvailable",
			getSKID: func(uid uuid.UUID) ([]byte, string, error) {
				return nil, ErrCertServerNotAvailable.Error(), ErrCertServerNotAvailable
			},
			signHash:   mockSign,
			StatusCode: http.StatusServiceUnavailable,
			ErrHeader:  ErrCodeCertServerNotAvailable,
			Content:    []byte(ErrCertServerNotAvailable.Error()),
		},
		{
			name: "getSKID ErrCertNotFound",
			getSKID: func(uid uuid.UUID) ([]byte, string, error) {
				return nil, ErrCertNotFound.Error(), ErrCertNotFound
			},
			signHash:   mockSign,
			StatusCode: http.StatusInternalServerError,
			ErrHeader:  ErrCodeCertNotFound,
			Content:    []byte(ErrCertNotFound.Error()),
		},
		{
			name: "getSKID ErrCertNotValid",
			getSKID: func(uid uuid.UUID) ([]byte, string, error) {
				return nil, ErrCertNotValid.Error(), ErrCertNotValid
			},
			signHash:   mockSign,
			StatusCode: http.StatusInternalServerError,
			ErrHeader:  ErrCodeCertNotValid,
			Content:    []byte(ErrCertNotValid.Error()),
		},
		{
			name: "getSKID unexpected error",
			getSKID: func(uid uuid.UUID) ([]byte, string, error) {
				return nil, testError.Error(), testError
			},
			signHash:   mockSign,
			StatusCode: http.StatusInternalServerError,
			ErrHeader:  ErrCodeCertGenericError,
			Content:    []byte(http.StatusText(http.StatusInternalServerError)),
		},
		{
			name:    "signHash bad",
			getSKID: mockGetSKID,
			signHash: func(uuid.UUID, []byte) ([]byte, error) {
				return nil, testError
			},
			StatusCode: http.StatusInternalServerError,
			ErrHeader:  ErrCodeCoseCreationFail,
			Content:    []byte(http.StatusText(http.StatusInternalServerError)),
		},
		{
			name:    "signHash nil signature",
			getSKID: mockGetSKID,
			signHash: func(uuid.UUID, []byte) ([]byte, error) {
				return nil, nil
			},
			StatusCode: http.StatusInternalServerError,
			ErrHeader:  ErrCodeCoseCreationFail,
			Content:    []byte(http.StatusText(http.StatusInternalServerError)),
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			coseSigner, err := NewCoseSigner(c.signHash, c.getSKID)
			require.NoError(t, err)

			msg := h.HTTPRequest{
				ID:      testUuid,
				Hash:    sha256.Sum256([]byte("test")),
				Payload: []byte("test"),
			}

			resp := coseSigner.Sign(msg)

			assert.Equal(t, c.StatusCode, resp.StatusCode)
			assert.Equal(t, c.ErrHeader, resp.Header.Get(h.ErrHeader))
			assert.Equal(t, c.Content, resp.Content)
		})
	}
}

func TestCoseSigner_GetSigStructBytes(t *testing.T) {
	coseSigner := CoseSigner{}
	_, err := coseSigner.GetSigStructBytes([]byte(""))
	assert.EqualError(t, err, "empty payload")
}

func TestCoseSigner_GetCBORFromJSON_Bad(t *testing.T) {
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

func mockGetSKID(uuid.UUID) ([]byte, string, error) {
	return testSKID, "", nil
}

func mockSign(uuid.UUID, []byte) ([]byte, error) {
	return testSignature, nil
}
