package http_server

import (
	"context"
	"encoding/json"
	"fmt"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server/helper"
	"net/http"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	log "github.com/sirupsen/logrus"
	prom "github.com/ubirch/ubirch-cose-client-go/main/prometheus"
)



type IdentityPayload struct {
	Uid string `json:"uuid"`
	Pwd string `json:"password"`
}

type InitializeIdentity func(ctx context.Context, uid uuid.UUID, auth string) (csr []byte, err error)

func Register(auth string, initialize InitializeIdentity) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(h.AuthHeader) != auth {
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

		timer := prometheus.NewTimer(prom.IdentityCreationDuration)
		csr, err := initialize(r.Context(), uid, idPayload.Pwd)
		timer.ObserveDuration()
		if err != nil {
			errMsg := fmt.Errorf("identity registration failed: %v", err)
			switch err {
			case h.ErrAlreadyInitialized:
				h.Error(uid, w, errMsg, http.StatusConflict)
			case h.ErrUnknown:
				h.Error(uid, w, errMsg, http.StatusNotFound)
			default:
				h.Error(uid, w, errMsg, http.StatusInternalServerError)
			}
			return
		}

		resp := h.HTTPResponse{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {h.BinType}},
			Content:    csr,
		}

		h.SendResponse(w, resp)

		prom.IdentityCreationCounter.Inc()
	}
}

func identityFromBody(r *http.Request) (IdentityPayload, error) {
	contentType := h.ContentType(r.Header)
	if contentType != h.JSONType {
		return IdentityPayload{}, fmt.Errorf("invalid content-type: expected %s, got %s", h.JSONType, contentType)
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
