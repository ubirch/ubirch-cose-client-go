package http_server

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	log "github.com/sirupsen/logrus"
	p "github.com/ubirch/ubirch-cose-client-go/main/prometheus"
)

const (
	RegisterEndpoint = "/register"
)

type IdentityRegisterer struct {
	auth string
}

type IdentityPayload struct {
	Uid string `json:"uuid"`
	Pwd string `json:"password"`
}

type StoreIdentity func(uid uuid.UUID, auth string) (csr []byte, err error)

type CheckIdentityExists func(uid uuid.UUID) (bool, error)

func NewIdentityRegisterer(auth string) IdentityRegisterer {
	return IdentityRegisterer{auth: auth}
}

func (i *IdentityRegisterer) Put(storeId StoreIdentity, idExists CheckIdentityExists) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(AuthHeader) != i.auth {
			log.Warnf("unauthorized registration attempt")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		idPayload, err := IdentityFromBody(r)
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

		exists, err := idExists(uid)
		if err != nil {
			log.Errorf("%s: %v", uid, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if exists {
			Error(uid, w, fmt.Errorf("identity already registered"), http.StatusConflict)
			return
		}

		timer := prometheus.NewTimer(p.IdentityCreationDuration)
		csr, err := storeId(uid, idPayload.Pwd)
		timer.ObserveDuration()
		if err != nil {
			log.Errorf("%s: %v", uid, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

		w.Header().Set("Content-Type", BinType)
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(csrPEM)
		if err != nil {
			log.Errorf("unable to write response: %s", err)
		}

		p.IdentityCreationCounter.Inc()
	}
}

func IdentityFromBody(r *http.Request) (IdentityPayload, error) {
	contentType := r.Header.Get("Content-Type")
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
