package http_server

import (
	"context"
	"fmt"
	"net/http"
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
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := c.httpServer.Serve(ctx)
			c.tcChecks(t, err)
		})
	}
}

func TestServe_Health_Ready(t *testing.T) {

	testCases := []struct {
		name      string
		reqUrl    string
		readyFunc func() error
		tcChecks  func(t *testing.T, err error, resp *http.Response)
	}{
		{
			name:   "happy path readyz",
			reqUrl: "http://localhost:1234/readyz",
			readyFunc: func() error {
				return nil
			},
			tcChecks: func(t *testing.T, err error, resp *http.Response) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		{
			name:   "happy path heathz",
			reqUrl: "http://localhost:1234/healthz",
			readyFunc: func() error {
				return nil
			},
			tcChecks: func(t *testing.T, err error, resp *http.Response) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		{
			name:   "error readiness func",
			reqUrl: "http://localhost:1234/readyz",
			readyFunc: func() error {
				return fmt.Errorf("something")
			},
			tcChecks: func(t *testing.T, err error, resp *http.Response) {
				require.NoError(t, err)
				require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			var readinessChecks []func() error
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			httpServer := HTTPServer{
				Router: NewRouter(),
				Addr:   "localhost:1234",
				TLS:    false,
			}

			readinessChecks = append(readinessChecks, c.readyFunc)

			httpServer.Router.Get("/healthz", Healthz("serverID"))
			httpServer.Router.Get("/readyz", Readyz("serverID", readinessChecks))

			go func() {
				err := httpServer.Serve(ctx)
				require.NoError(t, err)
			}()

			client := http.Client{}
			reqReady, err := http.NewRequest(http.MethodGet, c.reqUrl, nil)
			require.NoError(t, err)
			respReady, err := client.Do(reqReady)

			c.tcChecks(t, err, respReady)
		})
	}
}
