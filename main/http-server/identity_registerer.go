package http_server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	prom "github.com/ubirch/ubirch-cose-client-go/main/prometheus"
)

var (
	ErrAlreadyInitialized = errors.New("identity already registered")
	ErrUnknown            = errors.New("unknown identity")
)

type RegistrationPayload struct {
	Uid string `json:"uuid"`
	Pwd string `json:"password"`
}

type InitializeIdentity func(uid uuid.UUID) (csr []byte, pw string, err error)

func Register(registerAuth string, initialize InitializeIdentity) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get(AuthHeader)

		if auth == "" {
			Error(w, r, uuid.Nil, http.StatusUnauthorized, ErrCodeMissingAuth, fmt.Sprintf("missing authentication header %s", AuthHeader))
			return
		}

		if auth != registerAuth {
			Error(w, r, uuid.Nil, http.StatusUnauthorized, ErrCodeInvalidAuth, "invalid auth token")
			return
		}

		uid, err := identityFromBody(r)
		if err != nil {
			Error(w, r, uid, http.StatusBadRequest, ErrCodeInvalidRequestContent, err.Error())
			return
		}

		csr, auth, err := initialize(uid)
		if err != nil {
			switch err {
			case ErrAlreadyInitialized:
				Error(w, r, uid, http.StatusConflict, ErrCodeAlreadyInitialized, err.Error())
			case ErrUnknown:
				Error(w, r, uid, http.StatusNotFound, ErrCodeUnknownUUID, fmt.Sprintf("%v: identity can not be registered because there is no key with UUID %s present in the pkcs11 module (HSM)", err, uid))
			default:
				Error(w, r, uid, http.StatusInternalServerError, ErrCodeGenericInternalServerError, fmt.Sprintf("identity initialization failed: %v", err))
			}
			return
		}

		resp := HTTPResponse{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": {BinType},
				AuthHeader:     {auth},
			},
			Content: csr,
		}

		SendResponse(w, resp)

		prom.IdentityCreationCounter.Inc()
	}
}

func identityFromBody(r *http.Request) (uuid.UUID, error) {
	contentType := ContentType(r.Header)
	if contentType != JSONType {
		return uuid.Nil, fmt.Errorf("invalid content-type: expected: %s, got: %s", JSONType, contentType)
	}

	var payload RegistrationPayload
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {
		return uuid.Nil, err
	}
	if payload.Uid == "" {
		return uuid.Nil, fmt.Errorf("missing UUID in request content for identity registration")
	}
	if len(payload.Pwd) != 0 {
		return uuid.Nil, fmt.Errorf("attempt to set password for identity in registration request content: setting password is not longer supported, password will be generated and registered internally")
	}

	uid, err := uuid.Parse(payload.Uid)
	if err != nil {
		return uid, fmt.Errorf("parsing UUID failed: %v", err)
	}

	if uid.Version() < 1 || uid.Version() > 5 {
		return uid, fmt.Errorf("parsing UUID failed: invalid UUID version: expected 1 - 5, got %d", uid.Version())
	}

	if uid.Variant() != uuid.RFC4122 {
		return uid, fmt.Errorf("parsing UUID failed: invalid UUID variant: variant must comply with RFC4122: expected 0x8 - 0xb, got 0x%x (%s)", uid[8]>>4, uid.Variant().String())
	}

	return uid, nil
}
