package main

import (
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
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

	err := client.RegisterSeal(testUuid, testAuth)
	assert.NoError(t, err)
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

	err := client.RegisterSeal(testUuid, testAuth)
	assert.Error(t, err)
}

func TestCertifyApiClient_RegisterSeal_Fail(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder(
		http.MethodPost,
		mockCertifyApiURL+registerPath,
		httpmock.NewStringResponder(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)),
	)

	client := &CertifyApiClient{
		CertifyApiURL:  mockCertifyApiURL,
		CertifyApiAuth: mockCertifyApiAuth,
	}

	err := client.RegisterSeal(testUuid, testAuth)
	assert.Error(t, err)
}
