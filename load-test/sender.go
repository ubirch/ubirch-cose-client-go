package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
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
	return &Sender{
		httpClient:       &http.Client{Timeout: 30 * time.Second},
		statusCounter:    map[string]int{},
		statusCounterMtx: &sync.Mutex{},
		requestTimerMtx:  &sync.Mutex{},
	}
}

func (s *Sender) register(clientBaseURL, id, registerAuth string) (auth string, err error) {
	url := clientBaseURL + "register"

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

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(body))
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

	switch resp.StatusCode {
	case http.StatusOK:
		log.Infof("registered new identity: %s", id)
	case http.StatusConflict:
		log.Debugf("%s: identity already registered", id)
	default:
		return "", fmt.Errorf("%s: registration returned: %s", id, resp.Status)
	}

	return resp.Header.Get("X-Auth-Token"), nil
}

func (s *Sender) sendRequests(clientBaseURL, uid, auth string, offset time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()

	clientURL := clientBaseURL + uid + "/cbor/hash"
	header := http.Header{}
	header.Set("Content-Type", "application/octet-stream")
	header.Set("X-Auth-Token", auth)

	time.Sleep(offset)

	for i := 0; i < numberOfRequestsPerID; i++ {
		wg.Add(1)
		go s.sendAndCheckResponse(clientURL, header, wg)

		time.Sleep(time.Second / requestsPerSecondPerID)
	}
}

func (s *Sender) sendAndCheckResponse(clientURL string, header http.Header, wg *sync.WaitGroup) {
	defer wg.Done()

	hash := make([]byte, 32)
	rand.Read(hash)

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
	duration := time.Now().Sub(start)

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		s.addTime(duration)
	} else {
		respBodyBytes, _ := ioutil.ReadAll(resp.Body)
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
