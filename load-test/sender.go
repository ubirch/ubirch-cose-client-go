package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

type Sender struct {
	httpClient *http.Client
}

func NewSender() *Sender {
	return &Sender{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *Sender) register(id string, auth string, registerAuth string) error {
	url := clientBaseURL + "/register"

	header := http.Header{}
	header.Set("Content-Type", "application/json")
	header.Set("X-Auth-Token", registerAuth)

	registrationData := map[string]string{
		"uuid":     id,
		"password": auth,
	}

	body, err := json.Marshal(registrationData)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header = header

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		log.Infof("registered new identity: %s", id)
	case http.StatusConflict:
		log.Debugf("%s: identity already registered", id)
	default:
		log.Warnf("%s: registration returned: %s", id, resp.Status)
	}

	return nil
}

func (s *Sender) sendRequests(uid string, auth string, wg *sync.WaitGroup) {
	defer wg.Done()

	clientURL := clientBaseURL + uid + "/cbor/hash"
	header := http.Header{}
	header.Set("Content-Type", "application/octet-stream")
	header.Set("X-Auth-Token", auth)

	for i := 0; i < numberOfRequestsPerID; i++ {
		wg.Add(1)
		go s.sendAndCheckResponse(clientURL, header, wg)

		time.Sleep(time.Second / requestsPerSecondPerID)
	}
}

func (s *Sender) sendAndCheckResponse(clientURL string, header http.Header, wg *sync.WaitGroup) {
	defer wg.Done()

	hash := make([]byte, 32)
	_, err := rand.Read(hash)
	if err != nil {
		log.Error(err)
		return
	}

	err = s.sendRequest(clientURL, header, hash)
	if err != nil {
		log.Error(err)
		return
	}
}

func (s *Sender) sendRequest(clientURL string, header http.Header, hash []byte) error {
	req, err := http.NewRequest(http.MethodPost, clientURL, bytes.NewBuffer(hash))
	if err != nil {
		return err
	}

	req.Header = header

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf(resp.Status)
	}

	return nil
}
