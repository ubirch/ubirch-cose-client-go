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
	Uid uuid.UUID `json:"uuid"`
	Pwd string    `json:"password"`
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

		idPayload, err := identityFromBody(r)
		if err != nil {
			Error(w, r, idPayload.Uid, http.StatusBadRequest, ErrCodeInvalidRequestContent, err.Error())
			return
		}

		uid := idPayload.Uid

		csr, auth, err := initialize(uid)
		if err != nil {
			switch err {
			case ErrAlreadyInitialized:
				Error(w, r, uid, http.StatusConflict, ErrCodeAlreadyInitialized, err.Error())
			case ErrUnknown:
				Error(w, r, uid, http.StatusNotFound, ErrCodeUnknownUUID, err.Error())
			default:
				Error(w, r, uid, http.StatusInternalServerError, ErrCodeInternalServerError, fmt.Sprintf("identity initialization failed: %v", err))
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

func identityFromBody(r *http.Request) (RegistrationPayload, error) {
	contentType := ContentType(r.Header)
	if contentType != JSONType {
		return RegistrationPayload{}, fmt.Errorf("invalid content-type: expected %s, got %s", JSONType, contentType)
	}

	var payload RegistrationPayload
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {
		return RegistrationPayload{}, err
	}
	if payload.Uid == uuid.Nil {
		return RegistrationPayload{}, fmt.Errorf("missing UUID for identity registration")
	}
	if len(payload.Pwd) != 0 {
		return RegistrationPayload{}, fmt.Errorf("attempt to set password for identity in registration request content: setting password is not longer supported, password will be generated and registered internally")
	}
	return payload, nil
}
