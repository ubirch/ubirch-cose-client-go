package http_server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {

	byteStr := []byte("csr")

	testCases := []struct {
		name        string
		auth        string
		contentType string
		body        RegistrationPayload
		initId      InitializeIdentity
		tcChecks    func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name:        "happy path",
			auth:        testAuth,
			contentType: JSONType,
			body: RegistrationPayload{
				Uid: uuid.New(),
			},
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return byteStr, "", nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, string(byteStr), recorder.Body.String())
				require.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			name:        "wrong content type header",
			auth:        testAuth,
			contentType: BinType,
			body: RegistrationPayload{
				Uid: uuid.New(),
			},
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return byteStr, "", nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), "invalid content-type")
				require.Equal(t, http.StatusBadRequest, recorder.Code)
			},
		},
		{
			name:        "no uuid",
			auth:        testAuth,
			contentType: JSONType,
			body: RegistrationPayload{
				Uid: uuid.Nil,
			},
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return byteStr, "", nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), "missing UUID for identity registration")
				require.Equal(t, http.StatusBadRequest, recorder.Code)
			},
		},
		{
			name:        "no password",
			auth:        testAuth,
			contentType: JSONType,
			body: RegistrationPayload{
				Uid: uuid.New(),
				Pwd: "not supported anymore",
			},
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return byteStr, "", nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), "setting password is not longer supported")
				require.Equal(t, http.StatusBadRequest, recorder.Code)
			},
		},
		{
			name:        "missing auth",
			auth:        "",
			contentType: JSONType,
			body: RegistrationPayload{
				Uid: uuid.New(),
			},
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return byteStr, "", nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), "missing authentication header X-Auth-Token")
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
		},
		{
			name:        "invalid auth",
			auth:        "password",
			contentType: JSONType,
			body: RegistrationPayload{
				Uid: uuid.New(),
			},
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return byteStr, "", nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), "invalid auth token")
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
		},
		{
			name:        "conflict",
			auth:        testAuth,
			contentType: JSONType,
			body: RegistrationPayload{
				Uid: uuid.New(),
			},
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return nil, "", ErrAlreadyInitialized
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), ErrAlreadyInitialized.Error())
				require.Equal(t, http.StatusConflict, recorder.Code)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			router := chi.NewRouter()

			recorder := httptest.NewRecorder()
			router.Put(RegisterEndpoint, Register(testAuth, c.initId))

			payloadBuf := new(bytes.Buffer)
			err := json.NewEncoder(payloadBuf).Encode(c.body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPut, RegisterEndpoint, payloadBuf)
			req.Header.Add(AuthHeader, c.auth)
			req.Header.Add("Content-Type", c.contentType)

			router.ServeHTTP(recorder, req)
			c.tcChecks(t, recorder)
		})
	}
}
