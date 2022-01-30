package http_server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
				return testCSR, "1234", nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Empty(t, recorder.Header().Get(ErrHeader))
				assert.Equal(t, testCSR, recorder.Body.Bytes())
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
				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Equal(t, ErrCodeInvalidRequestContent, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "invalid content-type")
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
				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Equal(t, ErrCodeInvalidRequestContent, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "missing UUID for identity registration")
			},
		},
		{
			name:        "attempt to set password",
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
				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Equal(t, ErrCodeInvalidRequestContent, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "setting password is not longer supported")
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
				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Equal(t, ErrCodeMissingAuth, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "missing authentication header X-Auth-Token")
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
				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Equal(t, ErrCodeInvalidAuth, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "invalid auth token")
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
				assert.Equal(t, http.StatusConflict, recorder.Code)
				assert.Equal(t, ErrCodeAlreadyInitialized, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), ErrAlreadyInitialized.Error())
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
