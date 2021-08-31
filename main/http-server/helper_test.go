package http_server

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestHttpSuccess(t *testing.T) {
	failedTrue := HttpFailed(http.StatusHTTPVersionNotSupported)
	require.True(t, failedTrue)
	failedFalse := HttpFailed(http.StatusOK)
	require.False(t, failedFalse)
}

func TestContentEncoding(t *testing.T) {
	header := http.Header{}
	header.Set("Content-Transfer-Encoding", "BASE64")
	result := ContentEncoding(header)
	require.Equal(t, "base64", result)
}

func TestReadBody(t *testing.T) {
	bodyStr := "something"
	req, err := http.NewRequest("","", bytes.NewBufferString(bodyStr))
	require.NoError(t, err)

	body, err := ReadBody(req)
	require.NoError(t, err)
	require.Equal(t, bodyStr, string(body))
}
