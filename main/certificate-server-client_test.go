package main

import (
	"testing"

	"github.com/stretchr/testify/require"
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
			name:             "client with wrong server tls cert fingerprint",
			tlsCertFile:      "",
			CertSerURL:       "https://de.test.dscg.ubirch.com/trustList/DSC/DE/",
			CertSerPubKeyURL: "https://de.test.dscg.ubirch.com/pubkey.pem",
			tcChecks: func(t *testing.T, certs []Certificate, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "retrieving public key certificate list failed")
				require.Nil(t, certs)
			},
		},
		{
			name:             "client with wrong cert server url",
			tlsCertFile:      "demo_ubirch_tls_certs.json",
			CertSerURL:       "",
			CertSerPubKeyURL: "https://de.test.dscg.ubirch.com/pubkey.pem",
			tcChecks: func(t *testing.T, certs []Certificate, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "retrieving public key certificate list failed")
				require.Nil(t, certs)
			},
		},
		{
			name:             "client with wrong cert server url",
			tlsCertFile:      "demo_ubirch_tls_certs.json",
			CertSerURL:       "https://de.test.dscg.ubirch.com/trustList/DSC/DE/",
			CertSerPubKeyURL: "",
			tcChecks: func(t *testing.T, certs []Certificate, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "unable to retrieve public key for certificate list verification")
				require.Nil(t, certs)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			conf := &Config{}

			//no error handling since this is not the functionality we want to test
			conf.loadServerTLSCertificates(c.tlsCertFile)

			client := &CertificateServerClient{
				CertificateServerURL:       c.CertSerURL,
				CertificateServerPubKeyURL: c.CertSerPubKeyURL,
				ServerTLSCertFingerprints:  conf.serverTLSCertFingerprints,
			}

			certs, err := client.RequestCertificateList()
			c.tcChecks(t, certs, err)
		})
	}
}
