package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
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

func TestSkidHandler_LoadSKIDs(t *testing.T) {
	c := &ubirch.ECDSACryptoContext{}

	s := &SkidHandler{
		skidStore:      map[uuid.UUID][]byte{},
		skidStoreMutex: &sync.RWMutex{},

		certLoadFailCounter:  0,
		maxCertLoadFailCount: 3,

		getCerts:  mockGetCertificateListReturnsFewerCertsAfterFirstCall,
		getUuid:   mockGetUuid,
		encPubKey: c.EncodePublicKey,
	}

	s.loadSKIDs()

	len1 := len(s.skidStore)

	s.loadSKIDs()

	if len(s.skidStore) == len1 {
		t.Errorf("SKIDs were not overwritten")
	}
}

func TestSkidHandler_LoadSKIDs_BadGetCertificateList(t *testing.T) {
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

func TestSkidHandler_LoadSKIDs_BadGetCertificateList_MaxCertLoadFailCount(t *testing.T) {
	s := &SkidHandler{
		skidStore:      map[uuid.UUID][]byte{},
		skidStoreMutex: &sync.RWMutex{},

		certLoadFailCounter:  0,
		maxCertLoadFailCount: 3,

		getCerts: mockBadGetCertificateList,
	}

	testSkidStoreLen := 2
	for i := 1; i <= testSkidStoreLen; i++ {
		s.skidStore[uuid.New()] = make([]byte, 8)
	}

	for i := 1; i <= s.maxCertLoadFailCount; i++ {
		if len(s.skidStore) != testSkidStoreLen {
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

func TestSkidHandler_LoadSKIDs_CertificateValidity(t *testing.T) {
	s := NewSkidHandler(mockGetCertificateList, mockGetUuid, (&ubirch.ECDSACryptoContext{}).EncodePublicKey, false)

	require.False(t, containsSKID(s.skidStore, "DPMxfW4lzOE="))
	require.False(t, containsSKID(s.skidStore, "xOdxdmCwzas="))
	require.False(t, containsSKID(s.skidStore, "icUT/qzCb4M="))
}

func containsSKID(m map[uuid.UUID][]byte, v string) bool {
	for _, skid := range m {
		if base64.StdEncoding.EncodeToString(skid) == v {
			return true
		}
	}
	return false
}

var certs []Certificate

func mockGetCertificateList() ([]Certificate, error) {
	if len(certs) == 0 {
		filename := "test-cert-list.json"
		fileHandle, err := os.Open(filename)
		if err != nil {
			return nil, err
		}

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
	}

	return certs, nil
}

var alreadyCalled bool

func mockGetCertificateListReturnsFewerCertsAfterFirstCall() ([]Certificate, error) {
	if !alreadyCalled {
		alreadyCalled = true
		return mockGetCertificateList()
	} else {
		if len(certs) > 0 {
			return certs[:1], nil
		}
		return certs, nil
	}
}

func mockBadGetCertificateList() ([]Certificate, error) {
	return nil, test.Error
}

func mockGetUuid([]byte) (uuid.UUID, error) {
	newUUID := uuid.New()
	testUUIDs = append(testUUIDs, newUUID)
	return newUUID, nil
}

func mockGetUuidFindsNothing([]byte) (uuid.UUID, error) {
	return uuid.Nil, ErrNotExist
}
