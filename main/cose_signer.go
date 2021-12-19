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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fxamacker/cbor/v2" // imports as package "cbor"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ubirch/ubirch-cose-client-go/main/auditlogger"
	"golang.org/x/sync/semaphore"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	prom "github.com/ubirch/ubirch-cose-client-go/main/prometheus"
)

const (
	COSE_Alg_Label     = 1            // cryptographic algorithm identifier label (Common COSE Headers Parameters: https://cose-wg.github.io/cose-spec/#rfc.section.3.1)
	COSE_ES256_ID      = -7           // cryptographic algorithm identifier for ECDSA P-256 (https://cose-wg.github.io/cose-spec/#rfc.section.8.1)
	COSE_Kid_Label     = 4            // key identifier label (Common COSE Headers Parameters: https://cose-wg.github.io/cose-spec/#rfc.section.3.1)
	COSE_Sign1_Tag     = 18           // CBOR tag TBD7 identifies tagged COSE_Sign1 structure (https://cose-wg.github.io/cose-spec/#rfc.section.4.2)
	COSE_Sign1_Context = "Signature1" // signature context identifier for COSE_Sign1 structure (https://cose-wg.github.io/cose-spec/#rfc.section.4.4)
	ES256_Sig_Len      = 64           // length of ECDSA P-256 signatures in bytes
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

type SignHash func(id uuid.UUID, hash []byte) ([]byte, error)
type GetSKID func(uid uuid.UUID) ([]byte, error)

type CoseSigner struct {
	encMode         cbor.EncMode
	protectedHeader []byte
	signSem         *semaphore.Weighted
	SignHash
	GetSKID
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
		signSem:         semaphore.NewWeighted(1),
		SignHash:        sign,
		GetSKID:         skid,
	}, nil
}

func (c *CoseSigner) Sign(msg h.HTTPRequest) h.HTTPResponse {
	log.Debugf("%s: hash: %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	skid, err := c.GetSKID(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		var respStatusCode int
		switch err {
		case ErrCertServerNotAvailable:
			respStatusCode = http.StatusServiceUnavailable
		case ErrCertNotFound:
			respStatusCode = http.StatusTooEarly
		case ErrCertExpired:
			respStatusCode = http.StatusInternalServerError
		case ErrCertNotYetValid:
			respStatusCode = http.StatusTooEarly
		default:
			log.Errorf("CoseSigner.GetSKID returned unexpected error: %v", err)
			return h.ErrorResponse(http.StatusInternalServerError, "")
		}
		return h.ErrorResponse(respStatusCode, err.Error())
	}

	cose, err := c.createSignedCOSE(msg.Ctx, msg.ID, msg.Hash, skid, msg.Payload)
	if err != nil {
		log.Errorf("%s: could not create COSE object: %v", msg.ID, err)
		return h.ErrorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: COSE: %x", msg.ID, cose)

	infos := fmt.Sprintf("\"hwDeviceId\":\"%s\", \"hash\":\"%s\"", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))
	auditlogger.AuditLog("create", "COSE", infos)

	return h.HTTPResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {h.BinType}},
		Content:    cose,
	}
}

func (c *CoseSigner) createSignedCOSE(ctx context.Context, uid uuid.UUID, hash h.Sha256Sum, kid, payload []byte) ([]byte, error) {
	signature, err := c.getSignature(ctx, uid, hash)
	if err != nil {
		return nil, err
	}

	return c.getCOSE(kid, payload, signature)
}

func (c *CoseSigner) getSignature(ctx context.Context, uid uuid.UUID, hash h.Sha256Sum) ([]byte, error) {
	timerWait := prometheus.NewTimer(prom.SignatureCreationWithWaitDuration)
	defer timerWait.ObserveDuration()

	err := c.signSem.Acquire(ctx, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire semaphore for signing: %v", err)
	}
	defer c.signSem.Release(1)

	timerSign := prometheus.NewTimer(prom.SignatureCreationDuration)
	defer timerSign.ObserveDuration()

	sig, err := c.SignHash(uid, hash[:])
	if err != nil {
		prom.SignatureCreationFailCounter.Inc()
	} else {
		prom.SignatureCreationCounter.Inc()
	}
	return sig, err
}

// getCOSE creates a COSE Single Signer Data Object (COSE_Sign1)
// and returns the Canonical-CBOR-encoded object with tag 18
func (c *CoseSigner) getCOSE(kid, payload, signatureBytes []byte) ([]byte, error) {
	/*
		* https://cose-wg.github.io/cose-spec/#rfc.section.4.2
			[COSE Single Signer Data Object]

			The COSE_Sign1 structure is used when only one signature is going to be placed on a message.

			The structure can be encoded either tagged or untagged depending on the context it will be used in.
			A tagged COSE_Sign1 structure is identified by the CBOR tag TBD7. The CDDL fragment that represents this is:

			COSE_Sign1_Tagged = #6.18(COSE_Sign1)

			The COSE_Sign1 structure is a CBOR array. The fields of the array in order are:

			protected	as described in Section 3.
			unprotected	as described in Section 3.
			payload	    as described in Section 4.1.
			signature	contains the computed signature value. The type of the field is a bstr.

			The CDDL fragment that represents the above text for COSE_Sign1 follows.

			COSE_Sign1 = [
			    Headers,
			    payload : bstr / nil,
			    signature : bstr
			]

			* example: https://cose-wg.github.io/cose-spec/#Sign1_Examples

		* https://cose-wg.github.io/cose-spec/#rfc.section.3

				Headers = (
					protected : serialized_map,		# (b'\xA1\x01\x26')	=> {1: -7} => {"alg": ES256}
					unprotected : header_map		# \xA1\x04\x42\x31\x31 => {4: b'\x31\x31'} => {"kid": "11"}
				)

		* https://cose-wg.github.io/cose-spec/#rfc.section.4.4

			In order to create a signature, a well-defined byte stream is needed.
			The Sig_structure is used to create the canonical form.
			A Sig_structure is a CBOR array.

			The fields of the Sig_structure for COSE_Sign1 in order are:

			1. A text string identifying the context of the signature:
				"Signature1" for signatures using the COSE_Sign1 structure.

			2. The protected attributes from the body structure encoded in a bstr type.

			3. The protected attributes from the application encoded in a bstr type.
				If this field is not supplied, it defaults to a zero length binary string.

			4.The payload to be signed encoded in a bstr type.

			The CDDL fragment that describes the above text is:

				Sig_structure = [
					context : "Signature1",
					body_protected : serialized_map,	# (b'\xA1\x01\x26')	=> {1: -7}
					external_aad : bstr,				# (b'')
					payload : bstr						# (b'payload bytes')
				]

		* How to compute a signature:

			1. Create a Sig_structure and populate it with the appropriate fields.

			2. Create the value ToBeSigned by encoding the Sig_structure to a byte string, using the encoding described in Section 14.

			3. Call the signature creation algorithm passing in K (the key to sign with), alg (the algorithm to sign with), and ToBeSigned (the value to sign).

			4. Place the resulting signature value in the 'signature' field of the array.


		=> Pseudo-Code:
			sig_structure = ['Signature1', b'\xA1\x01\x26', b'', <payload>]			# (1.) out of scope
			hash = SHA256_hash(CBOR_encode(sig_structure))							# (2.)  normally, the hashing would be done in the next step, as part of
																							the signing, but since we do not want to know the original data,
																							the hashing should be done out of scope of this method
			signature = ECDSA_sign(hash)											# (3.) in scope
			COSE_Sign1 = [b'\xA1\x01\x26', {4: b'<uuid>'}, <payload>, signature]	# (4.) here we place the hash in the 'payload' field if original
																							payload is unknown
	*/
	if len(signatureBytes) != ES256_Sig_Len {
		return nil, fmt.Errorf("invalid signature length: expected %d, got %d", ES256_Sig_Len, len(signatureBytes))
	}

	// create COSE_Sign1 object
	coseSign1 := &COSE_Sign1{
		Protected:   c.protectedHeader,
		Unprotected: map[interface{}]interface{}{COSE_Kid_Label: kid},
		Payload:     payload,
		Signature:   signatureBytes,
	}

	// encode COSE_Sign1 object with tag
	return c.encMode.Marshal(cbor.Tag{Number: COSE_Sign1_Tag, Content: coseSign1})
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
