package http_server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"

	log "github.com/sirupsen/logrus"
	p "github.com/ubirch/ubirch-cose-client-go/main/prometheus"
)

var (
	ErrAlreadyInitialized = errors.New("identity already registered")
	ErrUnknown            = errors.New("no private key found")
)

type IdentityPayload struct {
	Uid string `json:"uuid"`
	Pwd string `json:"password"`
}

type InitializeIdentity func(uid uuid.UUID, auth string) (csr []byte, err error)

func Register(auth string, initialize InitializeIdentity) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(AuthHeader) != auth {
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

		uid, err := uuid.Parse(idPayload.Uid)
		if err != nil {
			log.Warnf("%s: %v", idPayload.Uid, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		timer := prometheus.NewTimer(p.IdentityCreationDuration)
		csr, err := initialize(uid, idPayload.Pwd)
		timer.ObserveDuration()
		if err != nil {
			errMsg := fmt.Errorf("identity registration failed: %v", err)
			switch err {
			case ErrAlreadyInitialized:
				Error(uid, w, errMsg, http.StatusConflict)
			case ErrUnknown:
				Error(uid, w, errMsg, http.StatusNotFound)
			default:
				Error(uid, w, errMsg, http.StatusInternalServerError)
			}
			return
		}

		resp := HTTPResponse{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {BinType}},
			Content:    csr,
		}

		SendResponse(w, resp)

		p.IdentityCreationCounter.Inc()
	}
}

func identityFromBody(r *http.Request) (IdentityPayload, error) {
	contentType := ContentType(r.Header)
	if contentType != JSONType {
		return IdentityPayload{}, fmt.Errorf("invalid content-type: expected %s, got %s", JSONType, contentType)
	}

	var payload IdentityPayload
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {
		return IdentityPayload{}, err
	}
	if len(payload.Uid) == 0 {
		return IdentityPayload{}, fmt.Errorf("empty uuid")
	}
	if len(payload.Pwd) == 0 {
		return IdentityPayload{}, fmt.Errorf("empty password")
	}
	return payload, nil
}
