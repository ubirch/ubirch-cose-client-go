package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

const numberOfValidCerts = 4

func TestNewSkidHandler(t *testing.T) {
	c := &ubirch.ECDSACryptoContext{}

	p := &Protocol{
		uuidCache: &sync.Map{},
	}

	s := NewSkidHandler(mockGetCertificateList, p.mockGetUuidForPublicKey, c.EncodePublicKey, false)

	assert.Equal(t, 3, s.maxCertLoadFailCount)
	assert.Equal(t, 0, s.certLoadFailCounter)
	assert.Equal(t, time.Hour, s.certLoadInterval)
	assert.Equal(t, numberOfValidCerts, len(s.skidStore))
}

func TestNewSkidHandler_ReloadEveryMinute(t *testing.T) {
	c := &ubirch.ECDSACryptoContext{}

	p := &Protocol{
		uuidCache: &sync.Map{},
	}

	s := NewSkidHandler(mockGetCertificateList, p.mockGetUuidForPublicKey, c.EncodePublicKey, true)

	assert.Equal(t, 60, s.maxCertLoadFailCount)
	assert.Equal(t, 0, s.certLoadFailCounter)
	assert.Equal(t, time.Minute, s.certLoadInterval)
	assert.Equal(t, numberOfValidCerts, len(s.skidStore))

	// the following lines test the scheduler to trigger the loadSKIDs method after one minute
	// since the execution of this test takes over a minute it is commented out
	//certs = certs[1:]
	//
	//time.Sleep(s.certLoadInterval + time.Second)
	//
	//assert.Equal(t, numberOfValidCerts-1, len(s.skidStore))
	//
	//// reset cert list
	//certs = []Certificate{}
}

func TestNewSkidHandler_GetUuidFindsNothing(t *testing.T) {
	c := &ubirch.ECDSACryptoContext{}

	s := NewSkidHandler(mockGetCertificateList, mockGetUuidFindsNothing, c.EncodePublicKey, true)

	assert.Empty(t, s.skidStore)
}

func TestSkidHandler_GetUuidReturnsError(t *testing.T) {
	c := &ubirch.ECDSACryptoContext{}

	s := NewSkidHandler(mockGetCertificateList, mockGetUuidReturnsError, c.EncodePublicKey, true)

	assert.Empty(t, s.skidStore)
}

func TestSkidHandler_LoadSKIDs(t *testing.T) {
	c := &ubirch.ECDSACryptoContext{}

	p := &Protocol{
		uuidCache: &sync.Map{},
	}

	s := &SkidHandler{
		skidStore:      map[uuid.UUID][]byte{},
		skidStoreMutex: &sync.RWMutex{},

		certLoadFailCounter:  0,
		maxCertLoadFailCount: 3,

		getCerts:  mockGetCertificateList,
		getUuid:   p.mockGetUuidForPublicKey,
		encPubKey: c.EncodePublicKey,
	}

	s.loadSKIDs()

	assert.Equal(t, numberOfValidCerts, len(s.skidStore))

	certs = certs[1:]

	s.loadSKIDs()

	assert.Equal(t, numberOfValidCerts-1, len(s.skidStore))

	// reset cert list
	certs = []Certificate{}
}

func TestSkidHandler_LoadSKIDs_BadGetCertificateList(t *testing.T) {
	s := &SkidHandler{
		skidStore:      map[uuid.UUID][]byte{},
		skidStoreMutex: &sync.RWMutex{},

		certLoadFailCounter:  0,
		maxCertLoadFailCount: 3,

		getCerts: mockGetCertificateListBad,
	}

	s.loadSKIDs()

	if len(s.skidStore) != 0 {
		t.Errorf("SKIDs were loaded with mockGetCertificateListBad")
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

		getCerts: mockGetCertificateListBad,
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
	c := &ubirch.ECDSACryptoContext{}

	p := &Protocol{
		uuidCache: &sync.Map{},
	}

	s := NewSkidHandler(mockGetCertificateList, p.mockGetUuidForPublicKey, c.EncodePublicKey, false)

	require.False(t, containsSKID(s.skidStore, "DPMxfW4lzOE="))
	require.False(t, containsSKID(s.skidStore, "xOdxdmCwzas="))
	require.False(t, containsSKID(s.skidStore, "icUT/qzCb4M="))
}

func TestSkidHandler_GetSKID(t *testing.T) {
	s := SkidHandler{
		skidStore:      map[uuid.UUID][]byte{},
		skidStoreMutex: &sync.RWMutex{},
	}

	for i := 0; i < 100; i++ {
		randSKID := make([]byte, 8)
		rand.Read(randSKID)
		s.skidStore[uuid.New()] = randSKID
	}

	wg := &sync.WaitGroup{}

	for uid, skid := range s.skidStore {
		wg.Add(1)
		go func(uid uuid.UUID, skid []byte, wg *sync.WaitGroup) {
			defer wg.Done()
			storedSKID, err := s.GetSKID(uid)
			require.NoError(t, err)
			assert.Equal(t, skid, storedSKID)
		}(uid, skid, wg)
	}

	wg.Wait()

	// check for unknown uuid
	_, err := s.GetSKID(uuid.New())
	assert.Error(t, err)
}

func TestSkidHandler_GetSKID2(t *testing.T) {
	s := SkidHandler{}

	s.isCertServerAvailable.Store(false)

	assert.False(t, s.isCertServerAvailable.Load().(bool))

	s.isCertServerAvailable.Store(true)

	assert.True(t, s.isCertServerAvailable.Load().(bool))
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

func mockGetCertificateListBad() ([]Certificate, error) {
	return nil, testError
}

func mockGetUuidFindsNothing([]byte) (uuid.UUID, error) {
	return uuid.Nil, ErrNotExist
}

func mockGetUuidReturnsError([]byte) (uuid.UUID, error) {
	return uuid.Nil, testError
}

func (p *Protocol) mockGetUuidForPublicKey(publicKeyPEM []byte) (uid uuid.UUID, err error) {
	pubKeyID := getPubKeyID(publicKeyPEM)

	_uid, found := p.uuidCache.Load(pubKeyID)

	if found {
		uid, found = _uid.(uuid.UUID)
	}

	if !found {
		uid = uuid.New()
		p.uuidCache.Store(pubKeyID, uid)
	}

	return uid, nil
}
