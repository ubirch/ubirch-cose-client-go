package http_server

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type GetCSR func(uid uuid.UUID) (csr []byte, err error)

func FetchCSR(registerAuth string, getUUID GetUUID, getCSR GetCSR) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get(AuthHeader)

		if auth == "" {
			Error(w, r, uuid.Nil, http.StatusUnauthorized, ErrCodeMissingAuth, fmt.Sprintf("missing authentication header %s", AuthHeader))
			return
		}

		uid, err := getUUID(r)
		if err != nil {
			Error(w, r, uid, http.StatusNotFound, ErrCodeInvalidUUID, err.Error())
			return
		}

		if auth != registerAuth {
			Error(w, r, uid, http.StatusUnauthorized, ErrCodeInvalidAuth, "invalid auth token")
			return
		}

		csr, err := getCSR(uid)
		if err != nil {
			switch err {
			case ErrUnknown:
				Error(w, r, uid, http.StatusNotFound, ErrCodeUnknownUUID, err.Error())
			default:
				Error(w, r, uid, http.StatusInternalServerError, ErrCodeGenericInternalServerError, fmt.Sprintf("generating CSR failed: %v", err))
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
