package http_server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var (
	testCSR = []byte{0x7, 0x21, 0x82, 0x81, 0x85, 0x5a, 0xd8, 0x68, 0x1d, 0xd, 0x86, 0xd1, 0xe9, 0x1e, 0x0, 0x16, 0x79, 0x39, 0xcb, 0x66, 0x94}
)

func TestFetchCSR(t *testing.T) {

	testUuid := uuid.New()
	testCases := []struct {
		name      string
		callerUrl string
		auth      string
		getCsR    GetCSR
		getUuid   GetUUID
		tcChecks  func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name:      "happy path",
			callerUrl: path.Join("/", testUuid.String(), CSREndpoint),
			auth:      testAuth,
			getCsR: func(uid uuid.UUID) (csr []byte, err error) {
				return testCSR, nil
			},
			getUuid: GetUUIDFromRequest,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Empty(t, recorder.Header().Get(ErrHeader))
				assert.Equal(t, testCSR, recorder.Body.Bytes())
			},
		},
		{
			name:      "missing auth",
			callerUrl: path.Join("/", uuid.NewString(), CSREndpoint),
			auth:      "",
			getCsR: func(uid uuid.UUID) (csr []byte, err error) {
				return testCSR, nil
			},
			getUuid: GetUUIDFromRequest,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Equal(t, ErrCodeMissingAuth, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "missing authentication header X-Auth-Token")
			},
		},
		{
			name:      "invalid auth",
			callerUrl: path.Join("/", uuid.NewString(), CSREndpoint),
			auth:      "password",
			getCsR: func(uid uuid.UUID) (csr []byte, err error) {
				return testCSR, nil
			},
			getUuid: GetUUIDFromRequest,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Equal(t, ErrCodeInvalidAuth, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "invalid auth token")
			},
		},
		{
			name:      "invalid uuid",
			callerUrl: path.Join("/", "2222", CSREndpoint),
			auth:      testAuth,
			getCsR: func(uid uuid.UUID) (csr []byte, err error) {
				return testCSR, nil
			},
			getUuid: GetUUIDFromRequest,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusNotFound, recorder.Code)
				assert.Equal(t, ErrCodeInvalidUUID, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "invalid UUID")
			},
		},
		{
			name:      "unknown uuid",
			callerUrl: path.Join("/", testUuid.String(), CSREndpoint),
			auth:      testAuth,
			getCsR: func(uid uuid.UUID) (csr []byte, err error) {
				return nil, ErrUnknown
			},
			getUuid: GetUUIDFromRequest,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusNotFound, recorder.Code)
				assert.Equal(t, ErrCodeUnknownUUID, recorder.Header().Get(ErrHeader))
				assert.Contains(t, recorder.Body.String(), "unknown identity")
			},
		},
		{
			name:      "internal server error",
			callerUrl: path.Join("/", testUuid.String(), CSREndpoint),
			auth:      testAuth,
			getCsR: func(uid uuid.UUID) (csr []byte, err error) {
				return nil, errors.New("unknown error")
			},
			getUuid: GetUUIDFromRequest,
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
			url := path.Join(UUIDPath, CSREndpoint)
			router.Get(url, FetchCSR(testAuth, c.getUuid, c.getCsR))

			req := httptest.NewRequest(http.MethodGet, c.callerUrl, nil)
			req.Header.Add(AuthHeader, c.auth)
			router.ServeHTTP(recorder, req)
			c.tcChecks(t, recorder)
		})
	}
}
