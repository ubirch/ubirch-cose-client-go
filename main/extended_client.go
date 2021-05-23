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

func (c *ExtendedClient) RequestCertificateList(verify Verify) ([]Certificate, error) {
	log.Debugf("requesting public key certificate list")

	resp, err := http.Get(c.CertificateServerURL)
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

	rest := []byte(respContent[1])

	ok, err := verify(pubKeyPEM, rest, signature)
	if err != nil {
		return nil, fmt.Errorf("unable to verify signature for public key certificate list: %v", err)
	}
	if !ok {
		return nil, fmt.Errorf("invalid signature for public key certificate list")
	}

	newTrustList := &trustList{}
	err = json.Unmarshal([]byte(respContent[1]), newTrustList)
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
