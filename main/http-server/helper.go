package http_server

import (
	"net/http"
	"strings"
)

// ContentType is a helper function to get "Content-Type" from request header
func ContentType(header http.Header) string {
	return strings.ToLower(header.Get("Content-Type"))
}

// ContentEncoding is a helper function to get "Content-Transfer-Encoding" from request header
func ContentEncoding(header http.Header) string {
	return strings.ToLower(header.Get("Content-Transfer-Encoding"))
}
