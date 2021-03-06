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

package http_server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

const (
	HexEncoding = "hex"
	HashLen     = 32
)

type Sha256Sum [HashLen]byte

type HTTPRequest struct {
	ID      uuid.UUID
	Hash    Sha256Sum
	Payload []byte
	Target  string
}

type CheckAuth func(uuid.UUID, string) (bool, bool, error)
type Sign func(HTTPRequest) HTTPResponse
type LogDebugSensitiveData func(string, ...interface{})

type COSEService struct {
	CheckAuth
	Sign
	LogDebugSensitiveData
}

type GetUUID func(*http.Request) (uuid.UUID, error)
type GetPayloadAndHash func(*http.Request) ([]byte, Sha256Sum, error)

func (s *COSEService) HandleRequest(getUUID GetUUID, getPayloadAndHash GetPayloadAndHash) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, err := getUUID(r)
		if err != nil {
			Error(w, r, uid, http.StatusNotFound, ErrCodeInvalidUUID, err.Error())
			return
		}

		auth := r.Header.Get(AuthHeader)

		if auth == "" {
			Error(w, r, uid, http.StatusUnauthorized, ErrCodeMissingAuth, fmt.Sprintf("missing authentication header %s", AuthHeader))
			return
		}

		authOk, found, err := s.CheckAuth(uid, auth)
		if err != nil {
			Error(w, r, uid, http.StatusInternalServerError, ErrCodeAuthInternalServerError, fmt.Sprintf("authentication check failed: %v", err))
			return
		}

		if !found {
			Error(w, r, uid, http.StatusNotFound, ErrCodeUnknownUUID, ErrUnknown.Error())
			return
		}

		if !authOk {
			Error(w, r, uid, http.StatusUnauthorized, ErrCodeInvalidAuth, "invalid auth token")
			return
		}

		msg := HTTPRequest{ID: uid, Target: r.URL.Path}

		msg.Payload, msg.Hash, err = getPayloadAndHash(r)
		if err != nil {
			Error(w, r, uid, http.StatusBadRequest, ErrCodeInvalidRequestContent, err.Error())
			return
		}
		s.LogDebugSensitiveData("%s: hash: %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))

		resp := s.Sign(msg)

		ctx := r.Context()
		select {
		case <-ctx.Done():
			log.Warnf("signing response can not be sent: http request %s", ctx.Err())
		default:
			SendResponse(w, resp)
		}
	}
}

func GetHashFromHashRequest() GetPayloadAndHash {
	return func(r *http.Request) (payload []byte, hash Sha256Sum, err error) {
		rBody, err := ReadBody(r)
		if err != nil {
			return nil, Sha256Sum{}, err
		}

		var data []byte

		contentType := ContentType(r.Header)
		switch contentType {
		case TextType:
			if ContentEncoding(r.Header) == HexEncoding {
				data, err = hex.DecodeString(string(rBody))
				if err != nil {
					return nil, Sha256Sum{}, fmt.Errorf("decoding hex encoded hash failed: %v (%s)", err, string(rBody))
				}
			} else {
				data, err = base64.StdEncoding.DecodeString(string(rBody))
				if err != nil {
					return nil, Sha256Sum{}, fmt.Errorf("decoding base64 encoded hash failed: %v (%s)", err, string(rBody))
				}
			}
		case BinType:
			data = rBody
		default:
			return nil, Sha256Sum{}, fmt.Errorf("invalid content-type for hash: "+
				"expected: (%s | %s), got: %s", BinType, TextType, contentType)
		}

		if len(data) != HashLen {
			return nil, Sha256Sum{}, fmt.Errorf("invalid SHA256 hash size: "+
				"expected: %d bytes, got: %d bytes", HashLen, len(data))
		}

		copy(hash[:], data)
		return data, hash, nil
	}
}

type GetCBORFromJSON func([]byte) ([]byte, error)
type GetSigStructBytes func([]byte) ([]byte, error)

func (s *COSEService) GetPayloadAndHashFromDataRequest(getCBORFromJSON GetCBORFromJSON, getSigStructBytes GetSigStructBytes) GetPayloadAndHash {
	return func(r *http.Request) (payload []byte, hash Sha256Sum, err error) {
		rBody, err := ReadBody(r)
		if err != nil {
			return nil, Sha256Sum{}, err
		}

		var data []byte

		contentType := ContentType(r.Header)
		switch contentType {
		case JSONType:
			data, err = getCBORFromJSON(rBody)
			if err != nil {
				return nil, Sha256Sum{}, fmt.Errorf("unable to CBOR encode JSON object: %v", err)
			}
		case CBORType:
			data = rBody
		default:
			return nil, Sha256Sum{}, fmt.Errorf("invalid content-type for original data: "+
				"expected: (%s | %s), got: %s", CBORType, JSONType, contentType)
		}
		s.LogDebugSensitiveData("CBOR: %x", data)

		toBeSigned, err := getSigStructBytes(data)
		if err != nil {
			return nil, Sha256Sum{}, err
		}
		s.LogDebugSensitiveData("toBeSigned: %x", toBeSigned)

		hash = sha256.Sum256(toBeSigned)
		return data, hash, err
	}
}
