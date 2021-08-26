package main

import (
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

const (
	mockCertifyApiURL  = "http://certify-api.com"
	mockCertifyApiAuth = "123456"
)

func TestCertifyApiClient_RegisterSeal(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder(
		http.MethodPost,
		mockCertifyApiURL+registerPath,
		httpmock.NewStringResponder(http.StatusCreated, http.StatusText(http.StatusCreated)),
	)

	client := &CertifyApiClient{
		CertifyApiURL:  mockCertifyApiURL,
		CertifyApiAuth: mockCertifyApiAuth,
	}

	err := client.RegisterSeal(test.Uuid, test.Auth)
	if err != nil {
		t.Error(err)
	}
}

func TestCertifyApiClient_RegisterSeal_AlreadyRegistered(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder(
		http.MethodPost,
		mockCertifyApiURL+registerPath,
		httpmock.NewStringResponder(http.StatusOK, http.StatusText(http.StatusOK)),
	)

	client := &CertifyApiClient{
		CertifyApiURL:  mockCertifyApiURL,
		CertifyApiAuth: mockCertifyApiAuth,
	}

	err := client.RegisterSeal(test.Uuid, test.Auth)
	if err == nil {
		t.Error("no error returned")
	}
}
