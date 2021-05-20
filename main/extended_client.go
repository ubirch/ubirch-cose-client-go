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
	CertificateServiceURL string
	SigningServiceURL     string
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
	Certificates []certificates `json:"certificates"`
}

type certificates struct {
	CertificateType string    `json:"certificateType"`
	Country         string    `json:"country"`
	Kid             []byte    `json:"kid"`
	RawData         []byte    `json:"rawData"`
	Signature       []byte    `json:"signature"`
	ThumbprintHEX   string    `json:"thumbprint"`
	Timestamp       time.Time `json:"timestamp"`
}

func (c *ExtendedClient) RequestCertificates() ([]certificates, error) {
	log.Debugf("requesting certificates from %s", c.CertificateServiceURL)

	resp, err := http.Get(c.CertificateServiceURL)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if h.HttpFailed(resp.StatusCode) {
		respBodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("retrieving certificates from %s failed: (%s) %s", c.CertificateServiceURL, resp.Status, string(respBodyBytes))
	}

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	respContent := strings.SplitN(string(respBodyBytes), "\n", 2)
	if len(respContent) != 2 {
		return nil, fmt.Errorf("unexpected response content")
	}

	signature, err := base64.StdEncoding.DecodeString(respContent[0])
	if err != nil {
		return nil, err
	}
	log.Debugf("signature: %s", base64.StdEncoding.EncodeToString(signature))
	// todo verify signature

	newTrustList := &trustList{}
	err = json.Unmarshal([]byte(respContent[1]), newTrustList)
	if err != nil {
		return nil, fmt.Errorf("unable to decode certificates list: %v", err)
	}

	return newTrustList.Certificates, nil
}
