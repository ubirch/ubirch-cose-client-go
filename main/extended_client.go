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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ubirch/ubirch-client-go/main/adapters/clients"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	urlpkg "net/url"
)

type ExtendedClient struct {
	clients.Client
	CertificateServerURL       string
	CertificateServerPubKeyURL string
	ServerTLSCertFingerprints  map[string][32]byte
}

type trustList struct {
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

func (c *ExtendedClient) RequestCertificateList(verify Verify) ([]Certificate, error) {
	respBodyBytes, err := c.getWithCertPinning(c.CertificateServerURL)
	if err != nil {
		return nil, fmt.Errorf("retrieving public key certificate list failed: %v", err)
	}

	respContent := strings.SplitN(string(respBodyBytes), "\n", 2)
	if len(respContent) < 2 {
		return nil, fmt.Errorf("unexpected response content from public key certificate server")
	}

	// verify signature
	pubKeyPEM, err := c.RequestCertificateListPublicKey()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve public key for certificate list verification: %v", err)
	}

	signature, err := base64.StdEncoding.DecodeString(respContent[0])
	if err != nil {
		return nil, fmt.Errorf("decoding signature of public key certificate list failed:: %v", err)
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
	resp, err := c.getWithCertPinning(c.CertificateServerPubKeyURL)
	if err != nil {
		return nil, fmt.Errorf("retrieving public key for certificate list verification failed: %v", err)
	}

	return resp, nil
}

func (c *ExtendedClient) getWithCertPinning(url string) ([]byte, error) {
	// get TLS certificate fingerprint for host
	u, err := urlpkg.Parse(url)
	if err != nil {
		return nil, err
	}
	tlsCertFingerprint, exists := c.ServerTLSCertFingerprints[u.Host]
	if !exists {
		return nil, fmt.Errorf("missing TLS certificate fingerprint for host %s", u.Host)
	}

	// set up TLS certificate verification
	client := &http.Client{}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			VerifyConnection: NewConnectionVerifier(tlsCertFingerprint),
		},
	}

	// make request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if h.HttpFailed(resp.StatusCode) {
		respBodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("response: (%s) %s", resp.Status, string(respBodyBytes))
	}

	return ioutil.ReadAll(resp.Body)
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
		serverCertFingerprint := sha256.Sum256(connectionState.PeerCertificates[0].RawSubjectPublicKeyInfo)

		if !bytes.Equal(serverCertFingerprint[:], fingerprint[:]) {
			return fmt.Errorf("pinned server TLS certificate mismatch")
		}

		return nil
	}
}
