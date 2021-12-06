package http_server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func TestHealth(t *testing.T) {
	const server = "test server"

	w := httptest.NewRecorder()

	Health(server)(w, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, server, w.Header().Get("Server"))
	assert.Equal(t, TextType, w.Header().Get("Content-Type"))
	assert.Equal(t, []byte(http.StatusText(http.StatusOK)), w.Body.Bytes())
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
			assert.Equal(t, TextType, w.Header().Get("Content-Type"))
			assert.Equal(t, []byte(http.StatusText(c.code)), w.Body.Bytes())
		})
	}
}
