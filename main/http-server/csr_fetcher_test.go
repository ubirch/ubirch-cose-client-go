package http_server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
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
				return uid.NodeID(), nil
			},
			getUuid: GetUUIDFromRequest,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, testUuid.NodeID(), recorder.Body.Bytes())
				require.Equal(t, http.StatusOK, recorder.Code)
			},
		},
		{
			name:      "unauthorized",
			callerUrl: path.Join("/", uuid.NewString(), CSREndpoint),
			auth:      "",
			getCsR: func(uid uuid.UUID) (csr []byte, err error) {
				return uid.NodeID(), nil
			},
			getUuid: GetUUIDFromRequest,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), http.StatusText(http.StatusUnauthorized))
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
			},
		},
		{
			name:      "invalid uuid",
			callerUrl: path.Join("/", "2222", CSREndpoint),
			auth:      testAuth,
			getCsR: func(uid uuid.UUID) (csr []byte, err error) {
				return uid.NodeID(), nil
			},
			getUuid: GetUUIDFromRequest,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Contains(t, recorder.Body.String(), "invalid UUID")
				require.Equal(t, http.StatusNotFound, recorder.Code)
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
				require.Contains(t, recorder.Body.String(), "unknown identity")
				require.Equal(t, http.StatusNotFound, recorder.Code)
			},
		},
		{
			name:      "unknown uuid internal server error",
			callerUrl: path.Join("/", testUuid.String(), CSREndpoint),
			auth:      testAuth,
			getCsR: func(uid uuid.UUID) (csr []byte, err error) {
				return nil, errors.New("unknown error")
			},
			getUuid: GetUUIDFromRequest,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.NotEmpty(t, recorder.Body.String())
				require.Equal(t, http.StatusInternalServerError, recorder.Code)
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