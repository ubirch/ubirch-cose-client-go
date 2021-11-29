package main

import (
	"testing"

	"github.com/ubirch/ubirch-cose-client-go/main/config"
)

func TestExtendedClient_RequestCertificateList(t *testing.T) {
	conf := &config.Config{}
	err := conf.LoadServerTLSCertificates("demo_ubirch_tls_certs.json")
	if err != nil {
		t.Fatalf("loading TLS certificates failed: %v", err)
	}

	client := &CertificateServerClient{
		CertificateServerURL:       "https://de.test.dscg.ubirch.com/trustList/DSC/DE/",
		CertificateServerPubKeyURL: "https://de.test.dscg.ubirch.com/pubkey.pem",
		ServerTLSCertFingerprints:  conf.ServerTLSCertFingerprints,
	}

	certs, err := client.RequestCertificateList()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Errorf("loaded empty certificate list without error")
	}
}
