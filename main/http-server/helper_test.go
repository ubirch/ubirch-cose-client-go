package http_server

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContentEncoding(t *testing.T) {
	header := http.Header{}
	header.Set("Content-Transfer-Encoding", "BASE64")
	result := ContentEncoding(header)
	require.Equal(t, "base64", result)
}

func TestReadBody(t *testing.T) {
	bodyStr := "something"
	req, err := http.NewRequest("", "", bytes.NewBufferString(bodyStr))
	require.NoError(t, err)

	body, err := ReadBody(req)
	require.NoError(t, err)
	require.Equal(t, bodyStr, string(body))
}
