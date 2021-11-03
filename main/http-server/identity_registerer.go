package http_server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
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

type InitializeIdentity func(ctx context.Context, uid uuid.UUID) (csr []byte, pw string, err error)

func Register(registerAuth string, initialize InitializeIdentity) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(AuthHeader) != registerAuth {
			log.Warnf("unauthorized registration attempt")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		idPayload, err := identityFromBody(r)
		if err != nil {
			log.Warn(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		uid := idPayload.Uid

		csr, auth, err := initialize(r.Context(), uid)
		if err != nil {
			switch err {
			case ErrAlreadyInitialized:
				Error(uid, w, err, http.StatusConflict)
			case ErrUnknown:
				Error(uid, w, err, http.StatusNotFound)
			default:
				log.Errorf("%s: identity registration failed: %v", uid, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		return RegistrationPayload{}, fmt.Errorf("empty uuid")
	}
	if len(payload.Pwd) != 0 {
		return RegistrationPayload{}, fmt.Errorf("setting password is not longer supported. password will be generated and registered automatically")
	}
	return payload, nil
}
