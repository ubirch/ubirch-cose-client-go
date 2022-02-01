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
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}

func ErrorResponse(uid uuid.UUID, httpCode int, errCode, errMsg string, exposeErrMsg bool) HTTPResponse {
	errLog, _ := json.Marshal(errorLog{
		Uid:        uid.String(),
		Error:      errMsg,
		ErrCode:    errCode,
		StatusCode: httpCode,
	})
	log.Errorf("ServerError: %s", errLog)

	header := http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
	if errCode != "" {
		header.Add(ErrHeader, errCode)
	}

	if !exposeErrMsg {
		errMsg = http.StatusText(httpCode)
	}

	return HTTPResponse{
		StatusCode: httpCode,
		Header:     header,
		Content:    []byte(errMsg),
	}
}

// Health is a liveness probe.
func Health(server string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", server)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
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
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, err := fmt.Fprintln(w, http.StatusText(status))
		if err != nil {
			log.Errorf("unable to write readiness response: %s, response was: %s", err, http.StatusText(status))
		}
	}
}

type errorLog struct {
	Uid        string `json:"sealID,omitempty"`
	Target     string `json:"target,omitempty"`
	Error      string `json:"error"`
	ErrCode    string `json:"errorCode,omitempty"`
	StatusCode int    `json:"statusCode"`
}

// Error is a wrapper for http.Error that additionally logs error context with logging
// level "warning" for client errors and logging level "error" for server errors.
// The error message for server errors will only be logged but not be sent to the client.
func Error(w http.ResponseWriter, r *http.Request, uid uuid.UUID, httpCode int, errCode, errMsg string) {
	e := errorLog{
		Target:     r.URL.Path,
		Error:      errMsg,
		ErrCode:    errCode,
		StatusCode: httpCode,
	}
	if uid != uuid.Nil {
		e.Uid = uid.String()
	}

	errLog, _ := json.Marshal(e)

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
		// this should never happen
		log.Errorf("error responder received unexpected HTTP response status code: %d, Error: %s", httpCode, errLog)
		http.Error(w, http.StatusText(httpCode), httpCode)
	}
}
