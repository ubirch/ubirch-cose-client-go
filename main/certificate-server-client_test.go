package main

import (
	"testing"
)

func TestExtendedClient_RequestCertificateList(t *testing.T) {
	conf := &Config{}
	err := conf.loadServerTLSCertificates("demo_ubirch_tls_certs.json")
	if err != nil {
		t.Fatalf("loading TLS certificates failed: %v", err)
	}

	client := &CertificateServerClient{
		CertificateServerURL:       "https://de.test.dscg.ubirch.com/trustList/DSC/DE/",
		CertificateServerPubKeyURL: "https://de.test.dscg.ubirch.com/pubkey.pem",
		ServerTLSCertFingerprints:  conf.serverTLSCertFingerprints,
	}

	certs, err := client.RequestCertificateList()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Errorf("loaded empty certificate list without error")
	}
}
