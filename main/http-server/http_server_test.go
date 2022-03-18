package http_server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServeError(t *testing.T) {

	testCases := []struct {
		name       string
		httpServer HTTPServer
		tcChecks   func(t *testing.T, err error)
	}{
		{
			name: "no cert file",
			httpServer: HTTPServer{
				Router: NewRouter(),
				Addr:   ":1234",
				TLS:    true,
			},
			tcChecks: func(t *testing.T, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "no such file or directory")
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			err := c.httpServer.Serve()
			c.tcChecks(t, err)
		})
	}
}
