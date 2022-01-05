package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

var (
	testSKID  = []byte{0xa3, 0x78, 0xce, 0x33, 0x3d, 0xd4, 0xf7, 0x76} // "o3jOMz3U93Y="
	testSKID2 = []byte{0x33, 0x3d, 0xd4, 0xf7, 0xa3, 0x78, 0xce, 0x76}
)

func TestSkidHandler(t *testing.T) {
	crypto := &ubirch.ECDSACryptoContext{Keystore: &MockKeystorer{}}

	uid := uuid.New()

	err := crypto.GenerateKey(uid)
	require.NoError(t, err)

	priv, err := crypto.Keystore.GetPrivateKey(uid)
	require.NoError(t, err)

	pub, err := crypto.Keystore.GetPublicKey(uid)
	require.NoError(t, err)

	testUUIDs := mockUuidCache{
		getPubKeyID(pub): uid,
	}

	testCases := []struct {
		name              string
		certs             GetCertificateList
		uid               GetUuid
		enc               EncodePublicKey
		reloadEveryMinute bool
		tcChecks          func(t *testing.T, s *SkidHandler)
	}{
		{
			name: "NewSkidHandler",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
			}),
			uid:               testUUIDs.mockGetUuidForPublicKey,
			enc:               crypto.EncodePublicKey,
			reloadEveryMinute: false,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				assert.Equal(t, 1, len(s.skidStore))

				assert.Equal(t, time.Hour, s.certLoadInterval)
				assert.Equal(t, 3, s.maxCertLoadFailCount)
				assert.Empty(t, s.certLoadFailCounter)

				assert.True(t, s.isCertServerAvailable.Load().(bool))

				skid, errMsg, err := s.GetSKID(uid)
				require.NoError(t, err)
				assert.Empty(t, errMsg)
				assert.Equal(t, testSKID, skid)

				_, errMsg, err = s.GetSKID(uuid.New())
				assert.Equal(t, ErrCertNotFound, err)
				assert.Contains(t, errMsg, ErrCertNotFound.Error())
			},
		},
		{
			name: "NewSkidHandler reloadEveryMinute",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
			}),
			uid:               testUUIDs.mockGetUuidForPublicKey,
			enc:               crypto.EncodePublicKey,
			reloadEveryMinute: true,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				assert.Equal(t, 1, len(s.skidStore))

				assert.Equal(t, time.Minute, s.certLoadInterval)
				assert.Equal(t, 60, s.maxCertLoadFailCount)
				assert.Empty(t, s.certLoadFailCounter)

				assert.True(t, s.isCertServerAvailable.Load().(bool))

				//// the following lines test the scheduler to trigger the loadSKIDs method after one minute
				//// since the execution of this test takes over a minute it is commented out
				//s.getCerts = mockGetCertificateList([]validity{})
				//
				//t.Logf("waiting %s for scheduler to reload certificate list...", s.certLoadInterval.String())
				//time.Sleep(s.certLoadInterval + time.Second)
				//
				//assert.Equal(t, 0, len(s.skidStore))
			},
		},
		{
			name: "loadSKIDs",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
			}),
			uid: testUUIDs.mockGetUuidForPublicKey,
			enc: crypto.EncodePublicKey,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				skid, errMsg, err := s.GetSKID(uid)
				require.NoError(t, err)
				assert.Empty(t, errMsg)
				require.Equal(t, testSKID, skid)

				s.getCerts = mockGetCertificateList([]validity{
					{
						PrivPEM:   priv,
						NotBefore: time.Now(),
						NotAfter:  time.Now().Add(time.Hour),
						SKID:      testSKID2,
					},
				})

				s.loadSKIDs()

				skid, errMsg, err = s.GetSKID(uid)
				require.NoError(t, err)
				assert.Empty(t, errMsg)
				assert.Equal(t, testSKID2, skid)
			},
		},
		{
			name:              "BadGetCertificateList",
			certs:             mockGetCertificateListBad,
			uid:               testUUIDs.mockGetUuidForPublicKey,
			enc:               crypto.EncodePublicKey,
			reloadEveryMinute: false,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				assert.Empty(t, s.skidStore)
				assert.Equal(t, 1, s.certLoadFailCounter)
				assert.False(t, s.isCertServerAvailable.Load().(bool))

				_, errMsg, err := s.GetSKID(uid)
				assert.Equal(t, ErrCertServerNotAvailable, err)
				assert.Contains(t, errMsg, ErrCertServerNotAvailable.Error())
				assert.Contains(t, errMsg, "trustList could not be loaded for 1h0m0s")
			},
		},
		{
			name: "BadGetCertificateList_MaxCertLoadFailCount",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
			}),
			uid:               testUUIDs.mockGetUuidForPublicKey,
			enc:               crypto.EncodePublicKey,
			reloadEveryMinute: true,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				s.getCerts = mockGetCertificateListBad

				for i := 0; i < s.maxCertLoadFailCount; i++ {
					assert.NotEmpty(t, len(s.skidStore))
					assert.Equal(t, i, s.certLoadFailCounter)

					s.loadSKIDs()
				}

				assert.Equal(t, s.maxCertLoadFailCount, s.certLoadFailCounter)
				assert.Empty(t, s.skidStore)
			},
		},
		{
			name: "invalid KID length",
			certs: func() ([]Certificate, error) {
				return []Certificate{{Kid: []byte{0x78, 0xce, 0x33, 0x3d, 0xd4, 0xf7, 0x76}}}, nil
			},
			uid: testUUIDs.mockGetUuidForPublicKey,
			enc: crypto.EncodePublicKey,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				assert.Empty(t, s.skidStore)
				assert.Empty(t, s.certLoadFailCounter)
				assert.True(t, s.isCertServerAvailable.Load().(bool))
			},
		},
		{
			name: "invalid certificate bytes",
			certs: func() ([]Certificate, error) {
				return []Certificate{{Kid: make([]byte, SkidLen), RawData: make([]byte, 64)}}, nil
			},
			uid: testUUIDs.mockGetUuidForPublicKey,
			enc: crypto.EncodePublicKey,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				assert.Empty(t, s.skidStore)
				assert.Empty(t, s.certLoadFailCounter)
				assert.True(t, s.isCertServerAvailable.Load().(bool))
			},
		},
		{
			name: "bad encPubKey",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
			}),
			uid: testUUIDs.mockGetUuidForPublicKey,
			enc: func(interface{}) ([]byte, error) {
				return nil, testError
			},
			tcChecks: func(t *testing.T, s *SkidHandler) {
				assert.Empty(t, s.skidStore)
				assert.Empty(t, s.certLoadFailCounter)
				assert.True(t, s.isCertServerAvailable.Load().(bool))
			},
		},
		{
			name: "GetUuidFindsNothing",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
			}),
			uid: mockGetUuidFindsNothing,
			enc: crypto.EncodePublicKey,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				assert.Empty(t, s.skidStore)
			},
		},
		{
			name: "GetUuidReturnsError",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
			}),
			uid: mockGetUuidReturnsError,
			enc: crypto.EncodePublicKey,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				assert.Empty(t, s.skidStore)
			},
		},
		{
			name: "certificate validity expired",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now().Add(-time.Hour),
					NotAfter:  time.Now().Add(-time.Minute),
					SKID:      testSKID,
				},
			}),
			uid: testUUIDs.mockGetUuidForPublicKey,
			enc: crypto.EncodePublicKey,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				_, errMsg, err := s.GetSKID(uid)
				assert.Equal(t, ErrCertExpired, err)
				assert.Contains(t, errMsg, ErrCertExpired.Error())
				assert.Contains(t, errMsg, s.skidStore[uid].NotAfter.String())
			},
		},
		{
			name: "certificate not yet valid",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now().Add(time.Minute),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
			}),
			uid: testUUIDs.mockGetUuidForPublicKey,
			enc: crypto.EncodePublicKey,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				_, errMsg, err := s.GetSKID(uid)
				assert.Equal(t, ErrCertNotYetValid, err)
				assert.Contains(t, errMsg, ErrCertNotYetValid.Error())
				assert.Contains(t, errMsg, s.skidStore[uid].NotBefore.String())
			},
		},
		{
			name: "do not overwrite previouslyMatchedSkid",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
				{
					PrivPEM:   priv,
					NotBefore: time.Now().Add(time.Minute),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID2,
				},
			}),
			uid: testUUIDs.mockGetUuidForPublicKey,
			enc: crypto.EncodePublicKey,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				skid, errMsg, err := s.GetSKID(uid)
				require.NoError(t, err)
				assert.Empty(t, errMsg)
				assert.Equal(t, testSKID, skid)
			},
		},
		{
			name: "use newer of two valid certificates",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
				{
					PrivPEM:   priv,
					NotBefore: time.Now().Add(-time.Hour),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID2,
				},
			}),
			uid: testUUIDs.mockGetUuidForPublicKey,
			enc: crypto.EncodePublicKey,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				skid, errMsg, err := s.GetSKID(uid)
				require.NoError(t, err)
				assert.Empty(t, errMsg)
				assert.Equal(t, testSKID, skid)
			},
		},
		{
			name: "use newer of two invalid certificates",
			certs: mockGetCertificateList([]validity{
				{
					PrivPEM:   priv,
					NotBefore: time.Now().Add(time.Minute),
					NotAfter:  time.Now().Add(time.Hour),
					SKID:      testSKID,
				},
				{
					PrivPEM:   priv,
					NotBefore: time.Now().Add(-time.Hour),
					NotAfter:  time.Now().Add(-time.Minute),
					SKID:      testSKID2,
				},
			}),
			uid: testUUIDs.mockGetUuidForPublicKey,
			enc: crypto.EncodePublicKey,
			tcChecks: func(t *testing.T, s *SkidHandler) {
				_, _, err := s.GetSKID(uid)
				assert.Equal(t, ErrCertNotYetValid, err)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			s := NewSkidHandler(c.certs, c.uid, c.enc, c.reloadEveryMinute)
			c.tcChecks(t, s)
		})
	}
}

func TestSkidHandler_GetSKID(t *testing.T) {
	s := SkidHandler{
		skidStore:      map[uuid.UUID]skidCtx{},
		skidStoreMutex: &sync.RWMutex{},
	}

	for i := 0; i < 100; i++ {
		randSKID := make([]byte, 8)
		_, err := rand.Read(randSKID)
		require.NoError(t, err)

		s.skidStore[uuid.New()] = skidCtx{
			SKID:  randSKID,
			Valid: true,
		}
	}

	wg := &sync.WaitGroup{}

	for uid, skid := range s.skidStore {
		wg.Add(1)
		go func(uid uuid.UUID, skid []byte, wg *sync.WaitGroup) {
			defer wg.Done()
			storedSKID, _, err := s.GetSKID(uid)
			require.NoError(t, err)
			assert.Equal(t, skid, storedSKID)
		}(uid, skid.SKID, wg)
	}

	wg.Wait()
}

func TestSkidHandler_LoadFromActualServer(t *testing.T) {
	conf := &config.Config{}
	err := conf.Load("", "config.json")
	if err != nil {
		t.Skipf("skipping %s: %v", t.Name(), err)
	}

	certClient := &CertificateServerClient{
		CertificateServerURL:       conf.CertificateServer,
		CertificateServerPubKeyURL: conf.CertificateServerPubKey,
		ServerTLSCertFingerprints:  conf.ServerTLSCertFingerprints,
	}

	protocol := &Protocol{uuidCache: &sync.Map{}}

	cryptoCtx := &ubirch.ECDSACryptoContext{Keystore: &MockKeystorer{}}

	skidHandler := NewSkidHandler(certClient.RequestCertificateList, protocol.mockGetUuidForPublicKey,
		cryptoCtx.EncodePublicKey, false)

	assert.Empty(t, skidHandler.certLoadFailCounter)
	assert.NotEmpty(t, skidHandler.skidStore)
}

type validity struct {
	PrivPEM   []byte
	NotBefore time.Time
	NotAfter  time.Time
	SKID      []byte
}

func mockGetCertificateList(v []validity) GetCertificateList {
	return func() ([]Certificate, error) {
		var certList []Certificate

		for _, valid := range v {

			priv, err := decodePrivateKey(valid.PrivPEM)
			if err != nil {
				panic(err)
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1342),
				NotBefore:    valid.NotBefore,
				NotAfter:     valid.NotAfter,
			}

			certificate, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
			if err != nil {
				panic(err)
			}

			certList = append(certList, Certificate{
				Kid:     valid.SKID,
				RawData: certificate,
			})

		}
		return certList, nil
	}
}

// decodePrivateKey decodes a Private Key from the x509 PEM format and returns the Private Key
func decodePrivateKey(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, fmt.Errorf("unable to parse PEM block")
	}
	x509Encoded := block.Bytes
	return x509.ParseECPrivateKey(x509Encoded)
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

type mockUuidCache map[string]uuid.UUID

func (m *mockUuidCache) mockGetUuidForPublicKey(publicKeyPEM []byte) (uuid.UUID, error) {
	pubKeyID := getPubKeyID(publicKeyPEM)

	uid, found := (*m)[pubKeyID]

	if !found {
		return uuid.Nil, ErrNotExist
	}

	return uid, nil
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
