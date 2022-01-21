package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
)

func TestExtendedClient_RequestCertificateList(t *testing.T) {
	testCases := []struct {
		name             string
		tlsCertFile      string
		CertSerURL       string
		CertSerPubKeyURL string
		tcChecks         func(t *testing.T, certs []Certificate, err error)
	}{
		{
			name:             "happy path",
			tlsCertFile:      "demo_ubirch_tls_certs.json",
			CertSerURL:       "https://de.test.dscg.ubirch.com/trustList/DSC/DE/",
			CertSerPubKeyURL: "https://de.test.dscg.ubirch.com/pubkey.pem",
			tcChecks: func(t *testing.T, certs []Certificate, err error) {
				require.NoError(t, err)
				require.Greater(t, len(certs), 0)
			},
		},
		{
			name:             "invalid server tls cert",
			tlsCertFile:      "test_invalid_tls_certs.json",
			CertSerURL:       "https://de.test.dscg.ubirch.com/trustList/DSC/DE/",
			CertSerPubKeyURL: "https://de.test.dscg.ubirch.com/pubkey.pem",
			tcChecks: func(t *testing.T, certs []Certificate, err error) {
				require.Error(t, err)
				require.Equal(t, "request to https://de.test.dscg.ubirch.com/trustList/DSC/DE/ failed: Get \"https://de.test.dscg.ubirch.com/trustList/DSC/DE/\": pinned server TLS certificate mismatch", err.Error())
				require.Nil(t, certs)
			},
		},
		{
			name:             "wrong cert server url",
			tlsCertFile:      "demo_ubirch_tls_certs.json",
			CertSerURL:       "https://de.dev.dscg.ubirch.com/trustList/DSC/DE/",
			CertSerPubKeyURL: "https://de.test.dscg.ubirch.com/pubkey.pem",
			tcChecks: func(t *testing.T, certs []Certificate, err error) {
				require.Error(t, err)
				require.Equal(t, "request to https://de.dev.dscg.ubirch.com/trustList/DSC/DE/ failed: missing TLS certificate fingerprint for host de.dev.dscg.ubirch.com", err.Error())
				require.Nil(t, certs)
			},
		},
		{
			name:             "wrong pubkey server url",
			tlsCertFile:      "demo_ubirch_tls_certs.json",
			CertSerURL:       "https://de.test.dscg.ubirch.com/trustList/DSC/DE/",
			CertSerPubKeyURL: "https://de.dev.dscg.ubirch.com/pubkey.pem",
			tcChecks: func(t *testing.T, certs []Certificate, err error) {
				require.Error(t, err)
				require.Equal(t, "unable to retrieve public key for trustList signature verification: request to https://de.dev.dscg.ubirch.com/pubkey.pem failed: missing TLS certificate fingerprint for host de.dev.dscg.ubirch.com", err.Error())
				require.Nil(t, certs)
			},
		},
		{
			name:             "cert server not found",
			tlsCertFile:      "demo_ubirch_tls_certs.json",
			CertSerURL:       "https://de.test.dscg.ubirch.com/invalidpath123",
			CertSerPubKeyURL: "https://de.test.dscg.ubirch.com/pubkey.pem",
			tcChecks: func(t *testing.T, certs []Certificate, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "request to https://de.test.dscg.ubirch.com/invalidpath123 failed: response: (404 Not Found)")
				require.Nil(t, certs)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			conf := &config.Config{}

			err := conf.LoadServerTLSCertificates(c.tlsCertFile)
			require.NoError(t, err)

			client := &CertificateServerClient{
				CertificateServerURL:       c.CertSerURL,
				CertificateServerPubKeyURL: c.CertSerPubKeyURL,
				ServerTLSCertFingerprints:  conf.ServerTLSCertFingerprints,
			}

			certs, err := client.RequestCertificateList()
			c.tcChecks(t, certs, err)
		})
	}
}

func TestHttpFailed(t *testing.T) {
	failedTrue := HttpFailed(http.StatusBadRequest)
	assert.True(t, failedTrue)

	failedFalse := HttpFailed(http.StatusOK)
	assert.False(t, failedFalse)
}

func TestHttpSuccess(t *testing.T) {
	successTrue := HttpSuccess(http.StatusOK)
	assert.True(t, successTrue)

	successTrue = HttpSuccess(http.StatusCreated)
	assert.True(t, successTrue)

	successFalse := HttpSuccess(http.StatusInternalServerError)
	assert.False(t, successFalse)
}
