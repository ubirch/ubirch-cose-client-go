package http_server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

const testTarget = "/test/target"

func TestSendResponse(t *testing.T) {
	header := http.Header{}
	header.Set("Content-Type", TextType)
	header.Set(AuthHeader, testAuth)

	resp := HTTPResponse{
		StatusCode: http.StatusTeapot,
		Header:     header,
		Content:    []byte("hello world"),
	}

	w := httptest.NewRecorder()

	SendResponse(w, resp)

	assert.Equal(t, resp.StatusCode, w.Code)
	assert.Equal(t, TextType, w.Header().Get("Content-Type"))
	assert.Equal(t, testAuth, w.Header().Get(AuthHeader))
	assert.Equal(t, resp.Content, w.Body.Bytes())
}

func TestErrorResponse(t *testing.T) {
	testCases := []struct {
		name         string
		httpCode     int
		errCode      string
		message      string
		exposeErrMsg bool
		respContent  string
	}{
		{
			name:         "bad request",
			httpCode:     http.StatusBadRequest,
			errCode:      ErrCodeInvalidRequestContent,
			message:      "this was a bad request",
			exposeErrMsg: true,
			respContent:  "this was a bad request",
		},
		{
			name:         "internal server error",
			httpCode:     http.StatusInternalServerError,
			errCode:      ErrCodeGenericInternalServerError,
			message:      "some internal error message",
			exposeErrMsg: false,
			respContent:  http.StatusText(http.StatusInternalServerError),
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {

			resp := ErrorResponse(testUUID, testTarget, c.httpCode, c.errCode, c.message, c.exposeErrMsg)

			assert.Equal(t, c.httpCode, resp.StatusCode)
			assert.Equal(t, c.errCode, resp.Header.Get(ErrHeader))
			assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
			assert.Equal(t, c.respContent, string(resp.Content))
		})
	}
}

func TestHealth(t *testing.T) {
	const server = "test server"

	w := httptest.NewRecorder()

	Health(server)(w, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, server, w.Header().Get("Server"))
	assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, []byte(http.StatusText(http.StatusOK)+"\n"), w.Body.Bytes())
}

func TestReady(t *testing.T) {

	testCases := []struct {
		name      string
		readyFunc func() error
		code      int
	}{
		{
			name: "happy path readyz",
			readyFunc: func() error {
				return nil
			},
			code: http.StatusOK,
		},
		{
			name: "error readiness func",
			readyFunc: func() error {
				return fmt.Errorf("something")
			},
			code: http.StatusServiceUnavailable,
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			const server = "test server"
			var readinessChecks []func() error

			readinessChecks = append(readinessChecks, c.readyFunc)

			w := httptest.NewRecorder()

			Ready(server, readinessChecks)(w, nil)

			assert.Equal(t, c.code, w.Code)
			assert.Equal(t, server, w.Header().Get("Server"))
			assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
			assert.Equal(t, []byte(http.StatusText(c.code)+"\n"), w.Body.Bytes())
		})
	}
}

func TestError(t *testing.T) {
	testCases := []struct {
		name        string
		uid         uuid.UUID
		httpCode    int
		errCode     string
		errMsg      string
		respContent string
	}{
		{
			name:        "client error",
			httpCode:    http.StatusBadRequest,
			errCode:     ErrCodeInvalidRequestContent,
			errMsg:      "bad request",
			respContent: "bad request",
		},
		{
			name:        "server error",
			httpCode:    http.StatusInternalServerError,
			errCode:     "",
			errMsg:      "server error",
			respContent: http.StatusText(http.StatusInternalServerError),
		},
		{
			name:        "invalid status code",
			httpCode:    0,
			errCode:     "",
			errMsg:      "some error",
			respContent: "",
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, testTarget, nil)

			Error(w, r, c.uid, c.httpCode, c.errCode, c.errMsg)

			assert.Equal(t, c.httpCode, w.Code)
			assert.Equal(t, c.errCode, w.Header().Get(ErrHeader))
			assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
			assert.Contains(t, w.Body.String(), c.respContent)
		})
	}
}
