// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/clients"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	urlpkg "net/url"
)

type ExtendedClient struct {
	clients.Client
	SigningServiceURL          string
	CertificateServerURL       string
	CertificateServerPubKeyURL string
}

func (c *ExtendedClient) SendToUbirchSigningService(uid uuid.UUID, auth string, upp []byte) (h.HTTPResponse, error) {
	endpoint := path.Join(c.SigningServiceURL, uid.String(), "hash")
	return clients.Post(endpoint, upp, UCCHeader(auth))
}

func UCCHeader(auth string) map[string]string {
	return map[string]string{
		"x-auth-token": auth,
		"content-type": "application/octet-stream",
	}
}

type trustList struct {
	//SignatureHEX string         `json:"signature"`
	Certificates []Certificate `json:"certificates"`
}

type Certificate struct {
	CertificateType string    `json:"certificateType"`
	Country         string    `json:"country"`
	Kid             []byte    `json:"kid"`
	RawData         []byte    `json:"rawData"`
	Signature       []byte    `json:"signature"`
	ThumbprintHEX   string    `json:"thumbprint"`
	Timestamp       time.Time `json:"timestamp"`
}

type Verify func(pubKeyPEM []byte, data []byte, signature []byte) (bool, error)

func (c *ExtendedClient) RequestCertificateList(tlsCertFingerprints map[string][32]byte, verify Verify) ([]Certificate, error) {
	log.Debugf("requesting public key certificate list")

	// get TLS certificate fingerprint for host
	url, err := urlpkg.Parse(c.CertificateServerURL)
	if err != nil {
		return nil, err
	}

	tlsCertFingerprint, exists := tlsCertFingerprints[url.Host]
	if !exists {
		return nil, fmt.Errorf("missing TLS certificate fingerprint for host %s", url.Host)
	}

	// set up TLS certificate verification
	client := &http.Client{}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			VerifyPeerCertificate: NewPeerCertificateVerifier(tlsCertFingerprint),
			VerifyConnection:      NewConnectionVerifier(tlsCertFingerprint),
		},
	}

	// make request
	req, err := http.NewRequest(http.MethodGet, c.CertificateServerURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if h.HttpFailed(resp.StatusCode) {
		respBodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("retrieving public key certificate list from %s failed: (%s) %s", c.CertificateServerURL, resp.Status, string(respBodyBytes))
	}

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	respContent := strings.SplitN(string(respBodyBytes), "\n", 2)
	if len(respContent) < 2 {
		return nil, fmt.Errorf("unexpected response content")
	}

	// verify signature
	pubKeyPEM, err := c.RequestCertificateListPublicKey()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve public key for certificate list verification: %v", err)
	}

	signature, err := base64.StdEncoding.DecodeString(respContent[0])
	if err != nil {
		return nil, err
	}

	certList := []byte(respContent[1])

	ok, err := verify(pubKeyPEM, certList, signature)
	if err != nil {
		return nil, fmt.Errorf("unable to verify signature for public key certificate list: %v", err)
	}
	if !ok {
		return nil, fmt.Errorf("invalid signature for public key certificate list")
	}

	newTrustList := &trustList{}
	err = json.Unmarshal(certList, newTrustList)
	if err != nil {
		return nil, fmt.Errorf("unable to decode public key certificate list: %v", err)
	}

	return newTrustList.Certificates, nil
}

func (c *ExtendedClient) RequestCertificateListPublicKey() ([]byte, error) {
	resp, err := http.Get(c.CertificateServerPubKeyURL)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if h.HttpFailed(resp.StatusCode) {
		respBodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("retrieving public key from %s failed: (%s) %s", c.CertificateServerPubKeyURL, resp.Status, string(respBodyBytes))
	}

	return ioutil.ReadAll(resp.Body)
}

// VerifyPeerCertificate is called after normal certificate verification by either a TLS client or server. It receives
// the raw ASN.1 certificates provided by the peer and also any verified chains that normal processing found.
// If it returns a non-nil error, the handshake is aborted and that error results.
//
// If normal verification fails then the handshake will abort before considering this callback.
type VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

func NewPeerCertificateVerifier(fingerprint [32]byte) VerifyPeerCertificate {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {

		serverCertFingerprint := sha256.Sum256(rawCerts[0])

		if !bytes.Equal(serverCertFingerprint[:], fingerprint[:]) {
			return fmt.Errorf("server TLS certificate mismatch: pinning failed")
		}

		return nil
	}
}

// VerifyConnection is called after normal certificate verification and after VerifyPeerCertificate by
// either a TLS client or server. If it returns a non-nil error, the handshake is aborted and that error results.
//
// If normal verification fails then the handshake will abort before considering this callback. This callback will run
// for all connections regardless of InsecureSkipVerify or ClientAuth settings.
type VerifyConnection func(connectionState tls.ConnectionState) error

func NewConnectionVerifier(fingerprint [32]byte) VerifyConnection {
	return func(connectionState tls.ConnectionState) error {

		// PeerCertificates are the parsed certificates sent by the peer, in the order in which they were sent.
		// The first element is the leaf certificate that the connection is verified against.
		serverCertFingerprint := sha256.Sum256(connectionState.PeerCertificates[0].Raw)

		if !bytes.Equal(serverCertFingerprint[:], fingerprint[:]) {
			return fmt.Errorf("server TLS certificate mismatch: pinning failed")
		}

		return nil
	}
}
