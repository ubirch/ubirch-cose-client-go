package repository

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type GetCertificateList func() ([]Certificate, error)
type EncodePublicKey func(pub interface{}) (pemEncoded []byte, err error)
type GetUuid func(pubKey []byte) (uuid.UUID, error)

type SkidHandler struct {
	skidStore      map[uuid.UUID][]byte
	skidStoreMutex *sync.RWMutex

	certLoadInterval     time.Duration
	maxCertLoadFailCount int
	certLoadFailCounter  int

	getCerts  GetCertificateList
	getUuid   GetUuid
	encPubKey EncodePublicKey
}

// NewSkidHandler loads SKIDs from the public key certificate list and updates it frequently
func NewSkidHandler(certs GetCertificateList, uid GetUuid, enc EncodePublicKey, reloadEveryMinute bool) *SkidHandler {
	s := &SkidHandler{
		skidStore:      map[uuid.UUID][]byte{},
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
	}

	tempSkidStore := map[uuid.UUID][]byte{}
	tempCerts := map[uuid.UUID]*x509.Certificate{}
	// go through certificate list and match known public keys
	for _, cert := range certs {
		kid := base64.StdEncoding.EncodeToString(cert.Kid)

		if len(cert.Kid) != SkidLen {
			log.Errorf("%s: invalid KID length: %d, expected: %d", kid, len(cert.Kid), SkidLen)
			continue
		}

		// get public key from certificate
		certificate, err := x509.ParseCertificate(cert.RawData)
		if err != nil {
			log.Errorf("%s: %v", kid, err)
			continue
		}

		pubKeyPEM, err := s.encPubKey(certificate.PublicKey)
		if err != nil {
			//log.Debugf("%s: unable to encode public key: %v", kid, err)
			continue
		}

		// look up matching UUID for public key
		uid, err := s.getUuid(pubKeyPEM)
		if err != nil {
			if err != ErrNotExist {
				log.Errorf("%s: %v", kid, err)
			}
			continue
		}
		//log.Debugf("%s: public key certificate match", kid)

		if certificate.NotAfter.After(time.Now()) {
			log.Debugf("certifcate expired %s: time now: %s", certificate.NotAfter.String(), time.Now().String())
			continue
		}

		if certificate.NotBefore.Before(time.Now()) {
			log.Debugf("certifcate not now valid NotBefore: %s time now: %s", certificate.NotAfter.String(), time.Now().String())
			continue
		}

		if tempCert, ok := tempCerts[uid]; ok {
			if certificate.NotBefore.Before(tempCert.NotBefore) {
				continue
			}
		}

		tempCerts[uid] = certificate
		tempSkidStore[uid] = cert.Kid
	}

	s.setSkidStore(tempSkidStore)
}

func (s *SkidHandler) setSkidStore(newSkidStore map[uuid.UUID][]byte) {
	s.skidStoreMutex.Lock()
	prevSKIDs, _ := json.Marshal(s.skidStore)
	s.skidStore = newSkidStore
	s.skidStoreMutex.Unlock()

	newSKIDs, _ := json.Marshal(newSkidStore)
	if !bytes.Equal(prevSKIDs, newSKIDs) {
		log.Infof("loaded %d matching certificates from server: %s", len(newSkidStore), newSKIDs)
	}
}

func (s *SkidHandler) GetSKID(uid uuid.UUID) ([]byte, error) {
	s.skidStoreMutex.RLock()
	skid, exists := s.skidStore[uid]
	s.skidStoreMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("SKID unknown for identity %s (missing X.509 public key certificate)", uid)
	}

	return skid, nil
}
