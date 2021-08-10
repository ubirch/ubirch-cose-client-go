package helper

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

const (
	GatewayTimeout  = 90 * time.Second // time after which a 504 response will be sent if no timely response could be produced
	ShutdownTimeout = 25 * time.Second // time after which the server will be shut down forcefully if graceful shutdown did not happen before
	ReadTimeout     = 1 * time.Second  // maximum duration for reading the entire request -> low since we only expect requests with small content
	WriteTimeout    = 99 * time.Second // time after which the connection will be closed if response was not written -> this should never happen
	IdleTimeout     = 60 * time.Second // time to wait for the next request when keep-alives are enabled

	UUIDKey          = "uuid"
	CBORPath         = "/cbor"
	HashEndpoint     = "/hash"
	RegisterEndpoint = "/register"
	CSREndpoint      = "/csr"

	ContentTypeKey = "Content-Type"
	BinType  = "application/octet-stream"
	TextType = "text/plain"
	JSONType = "application/json"
	CBORType = "application/cbor"

	AuthHeader = "X-Auth-Token"
)

var (
	ErrAlreadyInitialized = errors.New("identity already registered")
	ErrUnknown            = errors.New("unknown identity")
)

// ContentType is a helper function to get "Content-Type" from request header
func ContentType(header http.Header) string {
	return strings.ToLower(header.Get(ContentTypeKey))
}

// ContentEncoding is a helper function to get "Content-Transfer-Encoding" from request header
func ContentEncoding(header http.Header) string {
	return strings.ToLower(header.Get("Content-Transfer-Encoding"))
}

func HttpSuccess(StatusCode int) bool {
	return StatusCode >= 200 && StatusCode < 300
}

func HttpFailed(StatusCode int) bool {
	return !HttpSuccess(StatusCode)
}

// GetUUID returns the UUID parameter from the request URL
func GetUUID(r *http.Request) (uuid.UUID, error) {
	uuidParam := chi.URLParam(r, UUIDKey)
	uid, err := uuid.Parse(uuidParam)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID: \"%s\": %v", uuidParam, err)
	}
	return uid, nil
}

func ReadBody(r *http.Request) ([]byte, error) {
	rBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read request body: %v", err)
	}
	return rBody, nil
}
