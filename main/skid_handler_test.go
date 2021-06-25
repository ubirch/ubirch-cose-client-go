package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

var testUUIDs []uuid.UUID

func TestNewSkidHandler(t *testing.T) {
	c := &ubirch.ECDSACryptoContext{}

	s := NewSkidHandler(mockGetCertificateList, mockGetUuid, c.EncodePublicKey, false)

	if len(s.skidStore) != len(testUUIDs) {
		t.Errorf("loading SKIDs failed")
	}

	if s.maxCertLoadFailCount != 3 {
		t.Errorf("wrong interval set: %d, expected: 3", s.maxCertLoadFailCount)
	}

	if s.certLoadInterval != time.Hour {
		t.Errorf("wrong interval set: %s, expected: %s", s.certLoadInterval, time.Hour)
	}

	for _, uid := range testUUIDs {
		skid, err := s.GetSKID(uid)
		if err != nil {
			t.Error(err)
			return
		}
		if len(skid) != SkidLen {
			t.Error("stored SKID with invalid length")
		}
	}

	// check for unknown uuid
	_, err := s.GetSKID(uuid.New())
	if err == nil {
		t.Error("GetSKID did not return error for unknown UUID")
	}

	// clean up
	testUUIDs = []uuid.UUID{}
}

func mockGetCertificateList() ([]Certificate, error) {
	filename := "test-cert-list.json"
	fileHandle, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fileHandle.Close()

	var certs []Certificate
	err = json.NewDecoder(fileHandle).Decode(&certs)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

func mockGetUuid(pubKey []byte) (uuid.UUID, error) {
	newUUID := uuid.New()
	testUUIDs = append(testUUIDs, newUUID)
	return newUUID, nil
}
