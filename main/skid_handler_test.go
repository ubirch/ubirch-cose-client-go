package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
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

	if s.certLoadFailCounter != 0 {
		t.Errorf("s.certLoadFailCounter != 0: is %d", s.certLoadFailCounter)
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

func TestNewSkidHandler_ReloadEveryMinute(t *testing.T) {
	c := &ubirch.ECDSACryptoContext{}

	s := NewSkidHandler(mockGetCertificateList, mockGetUuidFindsNothing, c.EncodePublicKey, true)

	if len(s.skidStore) != 0 {
		t.Errorf("SKIDs were loaded with mockGetUuidFindsNothing")
	}

	if s.maxCertLoadFailCount != 60 {
		t.Errorf("wrong interval set: %d, expected: 60", s.maxCertLoadFailCount)
	}

	if s.certLoadFailCounter != 0 {
		t.Errorf("s.certLoadFailCounter != 0: is %d", s.certLoadFailCounter)
	}

	if s.certLoadInterval != time.Minute {
		t.Errorf("wrong interval set: %s, expected: %s", s.certLoadInterval, time.Minute)
	}
}

func TestNewSkidHandler_BadGetCertificateList(t *testing.T) {
	s := &SkidHandler{
		skidStore:      map[uuid.UUID][]byte{},
		skidStoreMutex: &sync.RWMutex{},

		certLoadFailCounter:  0,
		maxCertLoadFailCount: 3,

		getCerts: mockBadGetCertificateList,
	}

	s.loadSKIDs()

	if len(s.skidStore) != 0 {
		t.Errorf("SKIDs were loaded with mockBadGetCertificateList")
	}

	if s.certLoadFailCounter != 1 {
		t.Errorf("unexpected s.certLoadFailCounter value after 1 fail : %d", s.certLoadFailCounter)
	}
}

func TestNewSkidHandler_BadGetCertificateList_MaxCertLoadFailCount(t *testing.T) {
	s := &SkidHandler{
		skidStore:      map[uuid.UUID][]byte{},
		skidStoreMutex: &sync.RWMutex{},

		certLoadFailCounter:  0,
		maxCertLoadFailCount: 3,

		getCerts: mockBadGetCertificateList,
	}

	s.skidStore[uuid.New()] = make([]byte, 8)
	s.skidStore[uuid.New()] = make([]byte, 8)
	s.skidStore[uuid.New()] = make([]byte, 8)

	for i := 1; i <= s.maxCertLoadFailCount; i++ {
		if len(s.skidStore) != 3 {
			t.Errorf("SKIDs were cleared before maxCertLoadFailCount")
		}

		s.loadSKIDs()

		if s.certLoadFailCounter != i {
			t.Errorf("unexpected s.certLoadFailCounter value after %d fail : %d", i, s.certLoadFailCounter)
		}
	}

	if len(s.skidStore) != 0 {
		t.Errorf("SKIDs were not cleared after maxCertLoadFailCount")
	}
}

func mockGetCertificateList() ([]Certificate, error) {
	filename := "test-cert-list.json"
	fileHandle, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	var certs []Certificate
	err = json.NewDecoder(fileHandle).Decode(&certs)
	if err != nil {
		if fileCloseErr := fileHandle.Close(); fileCloseErr != nil {
			fmt.Print(fileCloseErr)
		}
		return nil, err
	}

	err = fileHandle.Close()
	if err != nil {
		return nil, err
	}

	return certs, nil
}

func mockBadGetCertificateList() ([]Certificate, error) {
	return nil, fmt.Errorf("test error")
}

func mockGetUuid(pubKey []byte) (uuid.UUID, error) {
	newUUID := uuid.New()
	testUUIDs = append(testUUIDs, newUUID)
	return newUUID, nil
}

func mockGetUuidFindsNothing(pubKey []byte) (uuid.UUID, error) {
	return uuid.Nil, ErrNotExist
}
