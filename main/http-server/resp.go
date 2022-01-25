package http_server

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

// SendResponse forwards a response to the client
func SendResponse(w http.ResponseWriter, resp HTTPResponse) {
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}

func ErrorResponse(httpCode int, errorCode, message string) HTTPResponse {
	if message == "" {
		message = http.StatusText(httpCode)
	}

	header := http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
	if errorCode != "" {
		header.Add(ErrHeader, errorCode)
	}

	return HTTPResponse{
		StatusCode: httpCode,
		Header:     header,
		Content:    []byte(message),
	}
}

// Health is a liveness probe.
func Health(server string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", server)
		w.Header().Set("Content-Type", TextType)
		w.WriteHeader(http.StatusOK)
		_, err := fmt.Fprintln(w, http.StatusText(http.StatusOK))
		if err != nil {
			log.Errorf("unable to write liveness response: %s, response was: %s", err, http.StatusText(http.StatusOK))
		}
	}
}

// Ready is a readiness probe.
func Ready(server string, readinessChecks []func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		status := http.StatusOK

		for _, isReady := range readinessChecks {
			if err := isReady(); err != nil {
				log.Warnf("readiness probe failed: %v", err)
				status = http.StatusServiceUnavailable
				break
			}
		}

		w.Header().Set("Server", server)
		w.Header().Set("Content-Type", TextType)
		w.WriteHeader(status)
		_, err := fmt.Fprintln(w, http.StatusText(status))
		if err != nil {
			log.Errorf("unable to write readiness response: %s, response was: %s", err, http.StatusText(status))
		}
	}
}

// Error is a wrapper for http.Error that additionally logs the error message to std.Output
func Error(uid uuid.UUID, w http.ResponseWriter, err error, code int) {
	log.Warnf("%s: %v", uid, err)
	http.Error(w, err.Error(), code)
}
