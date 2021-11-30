package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
)

func TestExtendedClient_RequestCertificateList(t *testing.T) {
	conf := &config.Config{}
	err := conf.LoadServerTLSCertificates("demo_ubirch_tls_certs.json")
	require.NoError(t, err)

	client := &CertificateServerClient{
		CertificateServerURL:       "https://de.test.dscg.ubirch.com/trustList/DSC/DE/",
		CertificateServerPubKeyURL: "https://de.test.dscg.ubirch.com/pubkey.pem",
		ServerTLSCertFingerprints:  conf.ServerTLSCertFingerprints,
	}

	certs, err := client.RequestCertificateList()
	require.NoError(t, err)
	assert.NotEqual(t, 0, len(certs))
}
