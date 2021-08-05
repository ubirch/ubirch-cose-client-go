package main

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	certificateServerURL       = "https://de.test.dscg.ubirch.com/trustList/DSC/DE/"
	certificateServerPubKeyURL = "https://de.test.dscg.ubirch.com/pubkey.pem"
)

func TestExtendedClient_RequestCertificateList(t *testing.T) {
	conf := &Config{}
	err := conf.loadServerTLSCertificates("demo_ubirch_tls_certs.json")
	if err != nil {
		t.Fatalf("loading TLS certificates failed: %v", err)
	}
	conf2 := &Config{}
	err = conf2.loadServerTLSCertificates("dev_ubirch_tls_certs.json")
	if err != nil {
		t.Fatalf("loading TLS certificates failed: %v", err)
	}
	cases := []struct {
		name          string
		client        *Client
		checkResponse func(t *testing.T, certs []Certificate, err error)
	}{
		{
			name:   "Success Path",
			client: createClient(certificateServerURL, certificateServerPubKeyURL, conf),
			checkResponse: func(t *testing.T, certs []Certificate, err error) {
				require.NoError(t, err)
				require.Greater(t, len(certs), 0)
			},
		},
		{
			name:   "Wrong or missing certificateServerUrl",
			client: createClient("", certificateServerPubKeyURL, conf),
			checkResponse: func(t *testing.T, certs []Certificate, err error) {
				fmt.Println(err)
				require.Error(t, err)
				require.Contains(t, err.Error(), "missing TLS")
				require.Equal(t, len(certs), 0)
			},
		},
		{
			name:   "Wrong or missing certificateServerPubKeyURL",
			client: createClient(certificateServerURL, "", conf),
			checkResponse: func(t *testing.T, certs []Certificate, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "retrieving public key for certificate list")
				require.Equal(t, len(certs), 0)
			},
		},
		{
			name:   "Empty config no local pinned cert",
			client: createClient(certificateServerURL, certificateServerPubKeyURL, &Config{}),
			checkResponse: func(t *testing.T, certs []Certificate, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "missing TLS certificate fingerprint for host de.test.dscg.ubirch.com")
				require.Equal(t, len(certs), 0)
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			certs, err := c.client.RequestCertificateList()
			c.checkResponse(t, certs, err)
		})
	}
}

func createClient(certificateServerURL, certificateServerPubKeyURL string, conf *Config) *Client {
	return &Client{
		CertificateServerURL:       certificateServerURL,
		CertificateServerPubKeyURL: certificateServerPubKeyURL,
		ServerTLSCertFingerprints:  conf.serverTLSCertFingerprints,
	}
}
