package http_server

import (
	"encoding/json"
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

type errorLog struct {
	Uid        uuid.UUID `json:"sealID,omitempty"`
	Path       string    `json:"path"`
	Error      string    `json:"error"`
	ErrCode    string    `json:"errorCode,omitempty"`
	StatusCode int       `json:"statusCode"`
}

// Error is a wrapper for http.Error that additionally logs uuid, request URL path, error message and status
// with logging level "warning" for client errors and "error" for server errors.
// The error message for server errors will only be logged but not be sent to the client.
func Error(w http.ResponseWriter, r *http.Request, uid uuid.UUID, httpCode int, errCode, errMsg string) {
	errLog, _ := json.Marshal(errorLog{
		Uid:        uid,
		Path:       r.URL.Path,
		Error:      errMsg,
		ErrCode:    errCode,
		StatusCode: httpCode,
	})

	if errCode != "" {
		w.Header().Set(ErrHeader, errCode)
	}

	switch true {
	case httpCode >= http.StatusBadRequest && httpCode < http.StatusBadRequest+100:
		log.Warnf("ClientError: %s", errLog)
		http.Error(w, errMsg, httpCode)
	case httpCode >= http.StatusInternalServerError && httpCode < http.StatusInternalServerError+100:
		log.Errorf("ServerError: %s", errLog)
		http.Error(w, http.StatusText(httpCode), httpCode)
	default:
		log.Errorf("unexpected HTTP response status code passed to error handler: %d, %s", httpCode, errLog)
		http.Error(w, http.StatusText(httpCode), httpCode)
	}
}
