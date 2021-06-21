package http_server

import (
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type GetCSR func(uid uuid.UUID) (csr []byte, err error)

func FetchCSR(get GetCSR) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, err := GetUUID(r)
		if err != nil {
			log.Warnf("FetchCSR: %v", err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		csr, err := get(uid)
		if err != nil {
			switch err {
			case ErrUnknown:
				Error(uid, w, err, http.StatusNotFound)
			default:
				Error(uid, w, err, http.StatusInternalServerError)
			}
			return
		}

		SendResponse(w, HTTPResponse{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {BinType}},
			Content:    csr,
		})
	}
}
