package http_server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server/helper"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegister(t *testing.T) {

	byteStr := []byte("csr")

	testCases := []struct {
		name        string
		auth        string
		contentType string
		body        IdentityPayload
		initId      InitializeIdentity
		tcChecks    func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name:        "happy path",
			auth:        testAuth,
			contentType: h.JSONType,
			body: IdentityPayload{
				Uid: uuid.NewString(),
				Pwd: "pass",
			},
			initId: func(ctx context.Context, uid uuid.UUID, auth string) (csr []byte, err error) {
				return byteStr, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, string(byteStr), recorder.Body.String())
				require.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			name:        "wrong content type header",
			auth:        testAuth,
			contentType: h.BinType,
			body: IdentityPayload{
				Uid: uuid.NewString(),
				Pwd: "pass",
			},
			initId: func(ctx context.Context, uid uuid.UUID, auth string) (csr []byte, err error) {
				return byteStr, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), "invalid content-type")
				require.Equal(t, http.StatusBadRequest, recorder.Code)
			},
		},
		{
			name:        "bad payload uuid",
			auth:        testAuth,
			contentType: h.JSONType,
			body: IdentityPayload{
				Uid: "bad uuid",
				Pwd: "pass",
			},
			initId: func(ctx context.Context, uid uuid.UUID, auth string) (csr []byte, err error) {
				return byteStr, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), "invalid UUID")
				require.Equal(t, http.StatusBadRequest, recorder.Code)
			},
		},
		{
			name:        "no uuid",
			auth:        testAuth,
			contentType: h.JSONType,
			body: IdentityPayload{
				Uid: "",
				Pwd: "pass",
			},
			initId: func(ctx context.Context, uid uuid.UUID, auth string) (csr []byte, err error) {
				return byteStr, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), "empty uuid")
				require.Equal(t, http.StatusBadRequest, recorder.Code)
			},
		},
		{
			name:        "no password",
			auth:        testAuth,
			contentType: h.JSONType,
			body: IdentityPayload{
				Uid: uuid.NewString(),
				Pwd: "",
			},
			initId: func(ctx context.Context, uid uuid.UUID, auth string) (csr []byte, err error) {
				return byteStr, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), "empty password")
				require.Equal(t, http.StatusBadRequest, recorder.Code)
			},
		},
		{
			name:        "not authorized",
			auth:        "",
			contentType: h.JSONType,
			body: IdentityPayload{
				Uid: uuid.NewString(),
				Pwd: "pass",
			},
			initId: func(ctx context.Context, uid uuid.UUID, auth string) (csr []byte, err error) {
				return byteStr, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), http.StatusText(http.StatusUnauthorized))
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
		},
		{
			name:        "conflict",
			auth:        testAuth,
			contentType: h.JSONType,
			body: IdentityPayload{
				Uid: uuid.NewString(),
				Pwd: "pass",
			},
			initId: func(ctx context.Context, uid uuid.UUID, auth string) (csr []byte, err error) {
				return nil, h.ErrAlreadyInitialized
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), h.ErrAlreadyInitialized.Error())
				require.Equal(t, http.StatusConflict, recorder.Code)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			router := chi.NewRouter()

			recorder := httptest.NewRecorder()
			router.Put(h.RegisterEndpoint, Register(testAuth, c.initId))

			payloadBuf := new(bytes.Buffer)
			err := json.NewEncoder(payloadBuf).Encode(c.body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPut, h.RegisterEndpoint, payloadBuf)
			req.Header.Add(h.AuthHeader, c.auth)
			req.Header.Add(h.ContentTypeKey, c.contentType)

			router.ServeHTTP(recorder, req)
			c.tcChecks(t, recorder)
		})
	}
}
