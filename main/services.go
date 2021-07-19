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
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ubirch/ubirch-cose-client-go/main/auditlogger"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
	prom "github.com/ubirch/ubirch-cose-client-go/main/prometheus"
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
}

type COSEService struct {
	*CoseSigner
	GetIdentity func(uuid.UUID) (Identity, error)
	CheckAuth   func([]byte, pw.Password) (bool, error)
}

type GetUUID func(*http.Request) (uuid.UUID, error)
type GetPayloadAndHash func(*http.Request) ([]byte, Sha256Sum, error)

func (s *COSEService) handleRequest(getUUID GetUUID, getPayloadAndHash GetPayloadAndHash) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, err := getUUID(r)
		if err != nil {
			log.Warn(err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		identity, err := s.GetIdentity(uid)
		if err == ErrNotExist {
			h.Error(uid, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
			return
		}
		if err != nil {
			log.Errorf("%s: %v", uid, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		auth := []byte(r.Header.Get(h.AuthHeader))

		timer := prometheus.NewTimer(prom.AuthCheckDuration)
		authOk, err := s.CheckAuth(auth, identity.PW)
		timer.ObserveDuration()

		if err != nil {
			log.Errorf("%s: password check failed: %v", uid, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !authOk {
			h.Error(uid, w, fmt.Errorf(http.StatusText(http.StatusUnauthorized)), http.StatusUnauthorized)
			return
		}

		msg := HTTPRequest{ID: uid}

		msg.Payload, msg.Hash, err = getPayloadAndHash(r)
		if err != nil {
			h.Error(msg.ID, w, err, http.StatusBadRequest)
			return
		}

		resp := s.Sign(msg)

		ctx := r.Context()
		select {
		case <-ctx.Done():
			log.Warnf("signing response can not be sent: http request %s", ctx.Err())
		default:
			h.SendResponse(w, resp)

			if h.HttpSuccess(resp.StatusCode) {
				infos := fmt.Sprintf("\"hwDeviceId\":\"%s\", \"hash\":\"%s\"", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))
				auditlogger.AuditLog("create", "COSE", infos)

				prom.SignatureCreationCounter.Inc()
			}
		}
	}
}

// getUUIDFromURL returns the UUID parameter from the request URL
func getUUIDFromURL(r *http.Request) (uuid.UUID, error) {
	uuidParam := chi.URLParam(r, h.UUIDKey)
	uid, err := uuid.Parse(uuidParam)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID: \"%s\": %v", uuidParam, err)
	}
	return uid, nil
}

func GetHashFromHashRequest() GetPayloadAndHash {
	return func(r *http.Request) (payload []byte, hash Sha256Sum, err error) {
		rBody, err := h.ReadBody(r)
		if err != nil {
			return nil, Sha256Sum{}, err
		}

		var data []byte

		switch h.ContentType(r.Header) {
		case h.TextType:
			if h.ContentEncoding(r.Header) == HexEncoding {
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
		case h.BinType:
			data = rBody
		default:
			return nil, Sha256Sum{}, fmt.Errorf("invalid content-type for hash: "+
				"expected (\"%s\" | \"%s\")", h.BinType, h.TextType)
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
		rBody, err := h.ReadBody(r)
		if err != nil {
			return nil, Sha256Sum{}, err
		}

		var data []byte

		switch h.ContentType(r.Header) {
		case h.JSONType:
			data, err = getCBORFromJSON(rBody)
			if err != nil {
				return nil, Sha256Sum{}, fmt.Errorf("unable to CBOR encode JSON object: %v", err)
			}
			log.Debugf("CBOR encoded JSON: %x", data)
		case h.CBORType:
			data = rBody
		default:
			return nil, Sha256Sum{}, fmt.Errorf("invalid content-type for original data: "+
				"expected (\"%s\" | \"%s\")", h.CBORType, h.JSONType)
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
