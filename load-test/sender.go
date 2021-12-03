package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	urlpkg "net/url"
)

type Sender struct {
	httpClient       *http.Client
	statusCounter    map[string]int
	statusCounterMtx *sync.Mutex
	requestTimer     time.Duration
	requestCounter   int
	requestTimerMtx  *sync.Mutex
}

func NewSender() *Sender {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 200
	transport.MaxConnsPerHost = 200
	transport.MaxIdleConnsPerHost = 200

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	return &Sender{
		httpClient:       client,
		statusCounter:    map[string]int{},
		statusCounterMtx: &sync.Mutex{},
		requestTimerMtx:  &sync.Mutex{},
	}
}

func (s *Sender) register(url urlpkg.URL, id, registerAuth string) (auth string, err error) {
	url.Path = path.Join(url.Path, "register")

	header := http.Header{}
	header.Set("Content-Type", "application/json")
	header.Set("X-Auth-Token", registerAuth)

	registrationData := map[string]string{
		"uuid": id,
	}

	body, err := json.Marshal(registrationData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPut, url.String(), bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header = header

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("%s: registration returned: %s: %s", id, resp.Status, respBody)
	}

	log.Infof("registered new identity: %s", id)

	auth = resp.Header.Get("X-Auth-Token")
	if auth == "" {
		return "", fmt.Errorf("%s: registration returned empty X-Auth-Token header: %s", id, resp.Status)
	}

	return auth, nil
}

func (s *Sender) sendRequests(url urlpkg.URL, uid, auth string, offset time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()

	url.Path = path.Join(url.Path, uid, "cbor/hash")

	header := http.Header{}
	header.Set("Content-Type", "application/octet-stream")
	header.Set("X-Auth-Token", auth)

	time.Sleep(offset)

	for i := 0; i < numberOfRequestsPerID; i++ {
		wg.Add(1)
		go s.sendAndCheckResponse(url.String(), header, wg)

		time.Sleep(time.Second / requestsPerSecondPerID)
	}
}

var hash = make([]byte, 32)

func (s *Sender) sendAndCheckResponse(clientURL string, header http.Header, wg *sync.WaitGroup) {
	defer wg.Done()

	req, err := http.NewRequest(http.MethodPost, clientURL, bytes.NewBuffer(hash))
	if err != nil {
		log.Error(err)
		return
	}

	req.Header = header

	start := time.Now()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Error(err)
		return
	}

	duration := time.Since(start)

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()
	respBodyBytes, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		s.addTime(duration)
	} else {
		log.Warnf("%d: %s", resp.StatusCode, respBodyBytes)
	}

	s.countStatus(resp.Status)
}

func (s *Sender) countStatus(status string) {
	s.statusCounterMtx.Lock()
	s.statusCounter[status] += 1
	s.statusCounterMtx.Unlock()
}

func (s *Sender) addTime(dur time.Duration) {
	s.requestTimerMtx.Lock()
	s.requestTimer += dur
	s.requestCounter += 1
	s.requestTimerMtx.Unlock()
}

func (s *Sender) getAvgRequestDuration() time.Duration {
	if s.requestCounter == 0 {
		return 0
	}
	return s.requestTimer / time.Duration(s.requestCounter)
}
