package http_server

import (
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
