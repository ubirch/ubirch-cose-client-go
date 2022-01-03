package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

var (
	TrustListErrorInfo        = "trustList (dscg server) related error"
	ErrCertServerNotAvailable = errors.New("server is not available")
	ErrCertNotFound           = errors.New("X.509 public key certificate for identity not found")
	ErrCertExpired            = errors.New("X.509 public key certificate for identity is expired")
	ErrCertNotYetValid        = errors.New("X.509 public key certificate for identity is not yet valid")
)

type skidCtx struct {
	SKID      []byte
	Valid     bool
	expired   bool
	NotBefore time.Time
	NotAfter  time.Time
}

type GetCertificateList func() ([]Certificate, error)
type EncodePublicKey func(pub interface{}) (pemEncoded []byte, err error)
type GetUuid func(pubKey []byte) (uuid.UUID, error)

type SkidHandler struct {
	skidStore      map[uuid.UUID]skidCtx
	skidStoreMutex *sync.RWMutex

	certLoadInterval     time.Duration
	maxCertLoadFailCount int
	certLoadFailCounter  int

	getCerts  GetCertificateList
	getUuid   GetUuid
	encPubKey EncodePublicKey

	isCertServerAvailable atomic.Value
}

// NewSkidHandler loads SKIDs from the public key certificate list and updates it frequently
func NewSkidHandler(certs GetCertificateList, uid GetUuid, enc EncodePublicKey, reloadEveryMinute bool) *SkidHandler {
	s := &SkidHandler{
		skidStore:      map[uuid.UUID]skidCtx{},
		skidStoreMutex: &sync.RWMutex{},

		certLoadFailCounter: 0,

		getCerts:  certs,
		getUuid:   uid,
		encPubKey: enc,
	}
	s.setInterval(reloadEveryMinute)

	s.loadSKIDs()

	// start scheduler
	go func() {
		for range time.Tick(s.certLoadInterval) {
			s.loadSKIDs()
		}
	}()

	return s
}

func (s *SkidHandler) setInterval(reloadEveryMinute bool) {
	if reloadEveryMinute {
		s.certLoadInterval = time.Minute
		s.maxCertLoadFailCount = 60
	} else {
		s.certLoadInterval = time.Hour
		s.maxCertLoadFailCount = 3
	}
}

func (s *SkidHandler) loadSKIDs() {
	certs, err := s.getCerts()
	if err != nil {
		log.Error(err)

		s.certLoadFailCounter++
		log.Debugf("loading certificate list failed %d times,"+
			" clearing local KID lookup after %d failed attempts",
			s.certLoadFailCounter, s.maxCertLoadFailCount)

		s.isCertServerAvailable.Store(false)

		// if we have not yet reached the maximum amount of failed attempts to load the certificate list,
		// return and try again later
		if s.certLoadFailCounter != s.maxCertLoadFailCount {
			return
		}

		// if we have reached the maximum amount of failed attempts to load the certificate list,
		// clear the SKID lookup
		log.Warnf("clearing local KID lookup after %d failed attempts to load public key certificate list",
			s.certLoadFailCounter)
	} else {
		// reset fail counter if certs were loaded successfully
		s.certLoadFailCounter = 0
		s.isCertServerAvailable.Store(true)
	}

	tempSkidStore := map[uuid.UUID]skidCtx{}

	// go through certificate list and match known public keys
	for _, cert := range certs {
		skidString := base64.StdEncoding.EncodeToString(cert.Kid)

		if len(cert.Kid) != SkidLen {
			log.Errorf("%s: invalid KID length: %d, expected: %d", skidString, len(cert.Kid), SkidLen)
			continue
		}

		// get public key from certificate
		certificate, err := x509.ParseCertificate(cert.RawData)
		if err != nil {
			log.Errorf("%s: parsing x509 certificate failed: %v", skidString, err)
			continue
		}

		pubKeyPEM, err := s.encPubKey(certificate.PublicKey)
		if err != nil {
			log.Debugf("%s: unable to encode public key from x509 certificate: %v", skidString, err)
			continue
		}

		// look up matching UUID for public key
		uid, err := s.getUuid(pubKeyPEM)
		if err != nil {
			if err == ErrNotExist {
				log.Debugf("%s: public key from x509 certificate does not match any known identity", skidString)
			} else {
				log.Errorf("%s: public key lookup failed: %v", skidString, err)
			}
			continue
		}
		log.Debugf("%s: public key match: %s", skidString, uid)

		matchedSkid := skidCtx{
			SKID:      cert.Kid,
			NotBefore: certificate.NotBefore,
			NotAfter:  certificate.NotAfter,
		}

		// check validity of certificate
		now := time.Now()

		if now.After(matchedSkid.NotAfter) {
			log.Debugf("%s: certifcate expired: valid until %s", skidString, matchedSkid.NotAfter.String())
			matchedSkid.expired = true
		} else if now.Before(matchedSkid.NotBefore) {
			log.Debugf("%s: certifcate not yet valid: valid from %s", skidString, matchedSkid.NotBefore.String())
		} else {
			matchedSkid.Valid = true
		}

		if previouslyMatchedSkid, ok := tempSkidStore[uid]; ok {
			if previouslyMatchedSkid.Valid && !matchedSkid.Valid {
				continue
			}

			// if there is more than one valid certificate, use the newer one, i.e. the one that starts being valid at a later time
			if (previouslyMatchedSkid.Valid && matchedSkid.Valid) || (!previouslyMatchedSkid.Valid && !matchedSkid.Valid) {
				if matchedSkid.NotBefore.Before(previouslyMatchedSkid.NotBefore) {
					continue
				}
			}
		}

		tempSkidStore[uid] = matchedSkid
	}

	s.setSkidStore(tempSkidStore)
}

func (s *SkidHandler) setSkidStore(newSkidStore map[uuid.UUID]skidCtx) {
	s.skidStoreMutex.Lock()
	prevSKIDs, _ := json.Marshal(s.skidStore)
	s.skidStore = newSkidStore
	s.skidStoreMutex.Unlock()

	newSKIDs, _ := json.Marshal(newSkidStore)
	if !bytes.Equal(prevSKIDs, newSKIDs) {
		log.Infof("loaded %d matching certificates from server: %s", len(newSkidStore), newSKIDs)
	}
}

func (s *SkidHandler) GetSKID(uid uuid.UUID) ([]byte, string, error) {
	s.skidStoreMutex.RLock()
	skid, exists := s.skidStore[uid]
	s.skidStoreMutex.RUnlock()

	if !exists {
		if !s.isCertServerAvailable.Load().(bool) {
			errMsg := fmt.Sprintf("%s: %v: trustList could not be loaded for %s",
				TrustListErrorInfo, ErrCertServerNotAvailable,
				(time.Duration(s.certLoadFailCounter) * s.certLoadInterval).String())
			return nil, errMsg, ErrCertServerNotAvailable
		}

		errMsg := fmt.Sprintf("%s: %v",
			TrustListErrorInfo, ErrCertNotFound)
		return nil, errMsg, ErrCertNotFound
	}

	if !skid.Valid {
		if skid.expired {
			errMsg := fmt.Sprintf("%s: %v: certificate was valid until %s",
				TrustListErrorInfo, ErrCertExpired, skid.NotAfter)
			return nil, errMsg, ErrCertExpired
		} else {
			errMsg := fmt.Sprintf("%s: %v: certificate will be valid from %s",
				TrustListErrorInfo, ErrCertNotYetValid, skid.NotBefore)
			return nil, errMsg, ErrCertNotYetValid
		}
	}

	return skid.SKID, "", nil
}
