package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type CertifyApiClient struct {
	CertifyApiURL  string
	CertifyApiAuth string
}

type SealRegistration struct {
	Uid uuid.UUID `json:"uuid"`
	Pwd string    `json:"password"`
}

// RegisterSeal registers a UUID and related auth token at the certify API
// https://github.com/ubirch/ubirch-certify-service#register-seal
func (c *CertifyApiClient) RegisterSeal(uid uuid.UUID, pwd string) error {
	client := &http.Client{Timeout: 3 * time.Second}

	sealRegBytes, err := json.Marshal(&SealRegistration{
		Uid: uid,
		Pwd: pwd,
	})
	if err != nil {
		return err
	}

	registerURL := c.CertifyApiURL + "/api/internal/identity/v1/seal/register"

	req, err := http.NewRequest(http.MethodPost, registerURL, bytes.NewBuffer(sealRegBytes))
	if err != nil {
		return err
	}

	req.Header.Set("X-Auth-Token", c.CertifyApiAuth)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusCreated:
		log.Debugf("%s: %q", uid, respBodyBytes)
		return nil
	case http.StatusOK:
		return fmt.Errorf("seal already registered at certify api (%q)", respBodyBytes)
	default:
		return fmt.Errorf("request to %s failed: (%d) %q", c.CertifyApiURL, resp.StatusCode, respBodyBytes)
	}
}
