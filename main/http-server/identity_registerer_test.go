package http_server

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {

	testCases := []struct {
		name        string
		auth        string
		contentType string
		body        []byte
		initId      InitializeIdentity
		tcChecks    func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name:        "happy path",
			auth:        testAuth,
			contentType: JSONType,
			body:        []byte("{\"uuid\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\"}"),
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
			name:        "missing auth",
			auth:        "",
			contentType: JSONType,
			body:        []byte("{\"uuid\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\"}"),
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return testCSR, "", nil
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
			body:        []byte("{\"uuid\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\"}"),
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return testCSR, "", nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Equal(t, ErrCodeInvalidAuth, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "invalid auth token")
			},
		},
		{
			name:        "wrong content type header",
			auth:        testAuth,
			contentType: BinType,
			body:        []byte("{\"uuid\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\"}"),
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return testCSR, "", nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Equal(t, ErrCodeInvalidRequestContent, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "invalid content-type")
			},
		},
		{
			name:        "invalid JSON",
			auth:        testAuth,
			contentType: BinType,
			body:        []byte("{\"uuid\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\"}"),
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return testCSR, "", nil
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
			body:        []byte("{}"),
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return testCSR, "", nil
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
			body:        []byte("{\"uuid\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\", \"password\": \"80d5aa1b-5623-466e-90b8-11a3d354b9ec\"}"),
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return testCSR, "", nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Equal(t, ErrCodeInvalidRequestContent, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "setting password is not longer supported")
			},
		},
		{
			name:        "conflict",
			auth:        testAuth,
			contentType: JSONType,
			body:        []byte("{\"uuid\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\"}"),
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return nil, "", ErrAlreadyInitialized
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusConflict, recorder.Code)
				assert.Equal(t, ErrCodeAlreadyInitialized, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), ErrAlreadyInitialized.Error())
			},
		},
		{
			name:        "unknown",
			auth:        testAuth,
			contentType: JSONType,
			body:        []byte("{\"uuid\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\"}"),
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return nil, "", ErrUnknown
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusNotFound, recorder.Code)
				assert.Equal(t, ErrCodeUnknownUUID, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), ErrUnknown.Error())
			},
		},
		{
			name:        "internal server error",
			auth:        testAuth,
			contentType: JSONType,
			body:        []byte("{\"uuid\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\"}"),
			initId: func(uid uuid.UUID) (csr []byte, pw string, err error) {
				return nil, "", errors.New("mock error")
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusInternalServerError, recorder.Code)
				assert.Equal(t, ErrCodeGenericInternalServerError, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), http.StatusText(http.StatusInternalServerError))
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			router := chi.NewRouter()

			recorder := httptest.NewRecorder()
			router.Put(RegisterEndpoint, Register(testAuth, c.initId))

			req := httptest.NewRequest(http.MethodPut, RegisterEndpoint, bytes.NewReader(c.body))
			req.Header.Add(AuthHeader, c.auth)
			req.Header.Add("Content-Type", c.contentType)

			router.ServeHTTP(recorder, req)
			c.tcChecks(t, recorder)
		})
	}
}
