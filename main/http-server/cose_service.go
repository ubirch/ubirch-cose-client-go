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
	"context"
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

	HashLen = 32
)

type Sha256Sum [HashLen]byte

type HTTPRequest struct {
	ID      uuid.UUID
	Hash    Sha256Sum
	Payload []byte
	Ctx     context.Context
}

type CheckAuth func(context.Context, uuid.UUID, string) (bool, bool, error)
type Sign func(HTTPRequest) HTTPResponse

type COSEService struct {
	CheckAuth
	Sign
}

type GetUUID func(*http.Request) (uuid.UUID, error)
type GetPayloadAndHash func(*http.Request) ([]byte, Sha256Sum, error)

func (s *COSEService) HandleRequest(getUUID GetUUID, getPayloadAndHash GetPayloadAndHash) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, err := getUUID(r)
		if err != nil {
			log.Warn(err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		ctx := r.Context()
		auth := r.Header.Get(AuthHeader)

		authOk, found, err := s.CheckAuth(ctx, uid, auth)
		if err != nil {
			log.Errorf("%s: password check failed: %v", uid, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !found {
			Error(uid, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
			return
		}

		if !authOk {
			Error(uid, w, fmt.Errorf("invalid auth token"), http.StatusUnauthorized)
			return
		}

		msg := HTTPRequest{ID: uid, Ctx: ctx}

		msg.Payload, msg.Hash, err = getPayloadAndHash(r)
		if err != nil {
			Error(msg.ID, w, err, http.StatusBadRequest)
			return
		}

		resp := s.Sign(msg)

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

		switch ContentType(r.Header) {
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
				"expected (\"%s\" | \"%s\")", BinType, TextType)
		}

		if len(data) != HashLen {
			return nil, Sha256Sum{}, fmt.Errorf("invalid SHA256 hash size: "+
				"expected %d bytes, got %d bytes", HashLen, len(data))
		}

		copy(hash[:], data)
		return data, hash, nil
	}
}

type GetCBORFromJSON func([]byte) ([]byte, error)
type GetSigStructBytes func([]byte) ([]byte, error)

func GetPayloadAndHashFromDataRequest(getCBORFromJSON GetCBORFromJSON, getSigStructBytes GetSigStructBytes) GetPayloadAndHash {
	return func(r *http.Request) (payload []byte, hash Sha256Sum, err error) {
		rBody, err := ReadBody(r)
		if err != nil {
			return nil, Sha256Sum{}, err
		}

		var data []byte

		switch ContentType(r.Header) {
		case JSONType:
			data, err = getCBORFromJSON(rBody)
			if err != nil {
				return nil, Sha256Sum{}, fmt.Errorf("unable to CBOR encode JSON object: %v", err)
			}
			log.Debugf("CBOR encoded JSON: %x", data)
		case CBORType:
			data = rBody
		default:
			return nil, Sha256Sum{}, fmt.Errorf("invalid content-type for original data: "+
				"expected (\"%s\" | \"%s\")", CBORType, JSONType)
		}

		toBeSigned, err := getSigStructBytes(data)
		if err != nil {
			return nil, Sha256Sum{}, err
		}
		log.Debugf("toBeSigned: %x", toBeSigned)

		hash = sha256.Sum256(toBeSigned)
		return data, hash, err
	}
}
