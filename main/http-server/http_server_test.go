package http_server

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestServeError(t *testing.T) {
	// set up HTTP server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpServer := HTTPServer{
		Router: NewRouter(),
		Addr:   ":1234",
		TLS:    true,
	}

	err := httpServer.Serve(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such file or directory")
}

func TestServeHealthReady(t *testing.T) {
	var readinessChecks []func() error
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpServer := HTTPServer{
		Router: NewRouter(),
		Addr:   "localhost:1234",
		TLS:    false,
	}

	readinessChecks = append(readinessChecks, func() error {
		return nil
	})

	httpServer.Router.Get("/healthz", Healthz("serverID"))
	httpServer.Router.Get("/readyz", Readyz("serverID", readinessChecks))

	go func() {
		err := httpServer.Serve(ctx)
		require.NoError(t, err)
	}()
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://localhost:1234/healthz", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	reqReady, err := http.NewRequest(http.MethodGet, "http://localhost:1234/readyz", nil)
	require.NoError(t, err)
	respReady, err := client.Do(reqReady)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respReady.StatusCode)
}

func TestServeNotReadyError(t *testing.T) {
	var readinessChecks []func() error
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpServer := HTTPServer{
		Router: NewRouter(),
		Addr:   "localhost:1234",
		TLS:    false,
	}

	readinessChecks = append(readinessChecks, func() error {
		return fmt.Errorf("something")
	})

	httpServer.Router.Get("/readyz", Readyz("serverID", readinessChecks))

	go func() {
		err := httpServer.Serve(ctx)
		require.NoError(t, err)
	}()
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://localhost:1234/readyz", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
