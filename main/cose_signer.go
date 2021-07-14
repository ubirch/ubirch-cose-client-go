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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fxamacker/cbor/v2" // imports as package "cbor"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

const (
	COSE_Alg_Label     = 1            // cryptographic algorithm identifier label (Common COSE Headers Parameters: https://cose-wg.github.io/cose-spec/#rfc.section.3.1)
	COSE_ES256_ID      = -7           // cryptographic algorithm identifier for ECDSA P-256 (https://cose-wg.github.io/cose-spec/#rfc.section.8.1)
	COSE_Kid_Label     = 4            // key identifier label (Common COSE Headers Parameters: https://cose-wg.github.io/cose-spec/#rfc.section.3.1)
	COSE_Sign1_Tag     = 18           // CBOR tag TBD7 identifies tagged COSE_Sign1 structure (https://cose-wg.github.io/cose-spec/#rfc.section.4.2)
	COSE_Sign1_Context = "Signature1" // signature context identifier for COSE_Sign1 structure (https://cose-wg.github.io/cose-spec/#rfc.section.4.4)
)

// 	COSE_Sign1 = [
// 		Headers,
//		payload : bstr / nil,
//		signature : bstr
//	]
// https://cose-wg.github.io/cose-spec/#rfc.section.4.2
type COSE_Sign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signature   []byte
}

//	Sig_structure = [
// 		context : "Signature1",
//		body_protected : serialized_map,
//		external_aad : bstr,
//		payload : bstr
//	]
// https://cose-wg.github.io/cose-spec/#rfc.section.4.4
type Sig_structure struct {
	_               struct{} `cbor:",toarray"`
	Context         string
	ProtectedHeader []byte
	External        []byte
	Payload         []byte
}

type SignHash func(privKeyPEM []byte, hash []byte) ([]byte, error)
type GetSKID func(uid uuid.UUID) ([]byte, error)
type Anchor func(uid uuid.UUID, auth string, data []byte) (h.HTTPResponse, error)

type CoseSigner struct {
	encMode         cbor.EncMode
	protectedHeader []byte
	SignHash
	GetSKID
	Anchor
}

func initCBOREncMode() (cbor.EncMode, error) {
	encOpt := cbor.CanonicalEncOptions() //https://cose-wg.github.io/cose-spec/#rfc.section.14
	return encOpt.EncMode()
}

func NewCoseSigner(sign SignHash, skid GetSKID) (*CoseSigner, error) {
	encMode, err := initCBOREncMode()
	if err != nil {
		return nil, err
	}

	protectedHeaderAlgES256 := map[uint8]int8{COSE_Alg_Label: COSE_ES256_ID}
	protectedHeaderAlgES256CBOR, err := encMode.Marshal(protectedHeaderAlgES256)
	if err != nil {
		return nil, err
	}

	return &CoseSigner{
		encMode:         encMode,
		protectedHeader: protectedHeaderAlgES256CBOR,
		SignHash:        sign,
		GetSKID:         skid,
	}, nil
}

func (c *CoseSigner) Sign(msg HTTPRequest, privateKeyPEM []byte, anchor bool) h.HTTPResponse {
	log.Debugf("%s: hash: %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	skid, err := c.GetSKID(msg.ID)
	if err != nil {
		log.Error(err)
		return errorResponse(http.StatusBadRequest, err.Error())
	}

	cose, err := c.createSignedCOSE(msg.Hash, privateKeyPEM, skid, msg.Payload)
	if err != nil {
		log.Errorf("could not create COSE object for identity %s: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: COSE: %x", msg.ID, cose)

	if anchor {
		coseStruct, err := decodeCose(cose)
		if err != nil {
			log.Error(err)
			return errorResponse(http.StatusInternalServerError, "")
		}

		resp, err := c.Anchor(msg.AnchorUuid, msg.AnchorAuth, coseStruct.Signature)
		if err != nil {
			log.Error(err)
			return errorResponse(http.StatusInternalServerError, "")
		}
		if h.HttpFailed(resp.StatusCode) {
			return resp
		}

		resp, err = c.Anchor(msg.AnchorUuid, msg.AnchorAuth, msg.Hash[:])
		if err != nil {
			log.Error(err)
			return errorResponse(http.StatusInternalServerError, "")
		}
		if h.HttpFailed(resp.StatusCode) {
			return resp
		}
	}

	return h.HTTPResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Content:    cose,
	}
}

func decodeCose(cose []byte) (*COSE_Sign1, error) {
	coseStruct := &COSE_Sign1{}
	dec := cbor.NewDecoder(bytes.NewReader(cose))
	err := dec.Decode(coseStruct)
	if err != nil {
		return nil, err
	}
	return coseStruct, nil
}

func (c *CoseSigner) createSignedCOSE(hash Sha256Sum, privateKeyPEM, kid, payload []byte) ([]byte, error) {
	timer := prometheus.NewTimer(prom.SignatureCreationDuration)
	signature, err := c.SignHash(privateKeyPEM, hash[:])
	timer.ObserveDuration()
	if err != nil {
		return nil, err
	}

	coseStruct, err := c.getCoseStruct(kid, payload, signature)
	if err != nil {
		return nil, err
	}

	// encode COSE_Sign1 object with tag
	return c.encMode.Marshal(cbor.Tag{Number: COSE_Sign1_Tag, Content: coseStruct})
}

// getCoseStruct creates a COSE Single Signer Data Object (COSE_Sign1)
// and returns the Canonical-CBOR-encoded object with tag 18
func (c *CoseSigner) getCoseStruct(kid, payload, signatureBytes []byte) (*COSE_Sign1, error) {
	if signatureBytes == nil {
		return nil, fmt.Errorf("empty signature")
	}

	return &COSE_Sign1{
		Protected:   c.protectedHeader,
		Unprotected: map[interface{}]interface{}{COSE_Kid_Label: kid},
		Payload:     payload,
		Signature:   signatureBytes,
	}, nil
}

// GetSigStructBytes creates a "Canonical CBOR"-encoded](https://tools.ietf.org/html/rfc7049#section-3.9)
// signature structure for a COSE_Sign1 object containing the given payload.
//
// Implements step 1 + 2 of the "How to compute a signature"-instructions from
// the [Signing and Verification Process](https://cose-wg.github.io/cose-spec/#rfc.section.4.4)
// and returns the ToBeSigned value.
func (c *CoseSigner) GetSigStructBytes(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	sigStruct := &Sig_structure{
		Context:         COSE_Sign1_Context,
		ProtectedHeader: c.protectedHeader,
		External:        []byte{}, // empty
		Payload:         payload,
	}

	// encode with "Canonical CBOR" rules -> https://tools.ietf.org/html/rfc7049#section-3.9
	return c.encMode.Marshal(sigStruct)
}

func (c *CoseSigner) GetCBORFromJSON(data []byte) ([]byte, error) {
	var reqDump map[string]string

	err := json.Unmarshal(data, &reqDump)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON request body: %v", err)
	}

	return c.encMode.Marshal(reqDump)
}
