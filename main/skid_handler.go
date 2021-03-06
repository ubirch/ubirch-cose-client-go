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

const timeLayout = "2006-01-02 15:04:05 -0700"

var (
	ErrCertServerNotAvailable = errors.New("dscg server (trustList) is not available")
	ErrCertNotFound           = errors.New("X.509 public key certificate for seal not found in trustList (dscg server)")
	ErrCertNotValid           = errors.New("X.509 public key certificate for seal from trustList (dscg server) is not valid")
)

type skidCtx struct {
	SKID      []byte
	Valid     bool
	expired   bool
	NotBefore time.Time
	NotAfter  time.Time
}

type LoadCertificateList func() ([]Certificate, error)
type EncodePublicKey func(pub interface{}) (pemEncoded []byte, err error)
type LookupUuid func(pubKey []byte) (uuid.UUID, error)

type SkidHandler struct {
	skidStore      map[uuid.UUID]skidCtx
	skidStoreMutex *sync.RWMutex

	certLoadInterval       time.Duration
	maxCertLoadFailCount   int
	certLoadFailCounter    int
	isCertServerAvailable  atomic.Value
	lastSuccessfulCertLoad time.Time

	loadCertList LoadCertificateList
	lookupUuid   LookupUuid
	encPubKey    EncodePublicKey

	logCertMismatch func(format string, args ...interface{})
}

// NewSkidHandler loads SKIDs from the public key certificate list and updates it frequently
func NewSkidHandler(certList LoadCertificateList, uid LookupUuid, enc EncodePublicKey, reloadEveryMinute, ignoreUnknownCerts bool) *SkidHandler {
	s := &SkidHandler{
		skidStore:      nil,
		skidStoreMutex: &sync.RWMutex{},

		loadCertList: certList,
		lookupUuid:   uid,
		encPubKey:    enc,
	}

	if ignoreUnknownCerts {
		s.logCertMismatch = log.Debugf
	} else {
		s.logCertMismatch = log.Warnf
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
	certList, err := s.loadCertList()
	if err != nil {
		log.Errorf("unable to retrieve public key certificate list (trustList) from dscg server: %v", err)
		s.handleCertListLoadFail()
		return
	}

	// reset fail counter if certs were loaded successfully
	s.certLoadFailCounter = 0
	s.isCertServerAvailable.Store(true)
	s.lastSuccessfulCertLoad = time.Now()

	tempSkidStore := map[uuid.UUID]skidCtx{}

	// go through certificate list and match known public keys
	for _, cert := range certList {
		uid, matchedSkid := s.matchCertificate(cert)
		if matchedSkid != nil {
			s.checkCertificateValidity(uid, matchedSkid, &tempSkidStore)
		}
	}

	s.updateSkidStore(tempSkidStore)
}

func (s *SkidHandler) handleCertListLoadFail() {
	s.certLoadFailCounter++
	s.isCertServerAvailable.Store(false)

	if !s.lastSuccessfulCertLoad.IsZero() {
		errMsg := fmt.Sprintf("trustList could not be loaded since %s (%s ago)", s.lastSuccessfulCertLoad.Format(timeLayout), time.Duration(s.certLoadFailCounter)*s.certLoadInterval)

		if s.certLoadFailCounter < s.maxCertLoadFailCount {
			// we have not yet reached the maximum amount of failed attempts to load the certificate list,
			// return and try again later
			log.Warnf(errMsg+", local SKID lookup will be cleared in %s if this issue persists",
				time.Duration(s.maxCertLoadFailCount-s.certLoadFailCounter)*s.certLoadInterval)
		} else if s.certLoadFailCounter == s.maxCertLoadFailCount {
			// we have reached the maximum amount of failed attempts to load the certificate list,
			// clear the SKID lookup
			log.Errorf(errMsg+", clearing local SKID lookup after %d failed attempts to load public key certificate list",
				s.certLoadFailCounter)

			s.resetSkidStore()
		} else {
			// we surpassed the maximum amount of failed attempts to load the certificate list,
			// SKID lookup has been cleared
			log.Warnf(errMsg+", local SKID lookup was cleared %s ago",
				time.Duration(s.certLoadFailCounter-s.maxCertLoadFailCount)*s.certLoadInterval)
		}
	}
}

func (s *SkidHandler) matchCertificate(cert Certificate) (uuid.UUID, *skidCtx) {
	skidString := base64.StdEncoding.EncodeToString(cert.Kid)
	errPrefix := fmt.Sprintf("an error occurred while trying to match X.509 public key certificate with KID %s", skidString)

	if len(cert.Kid) != SkidLen {
		log.Errorf("%s: invalid KID length: expected: %d bytes, got: %d bytes", errPrefix, SkidLen, len(cert.Kid))
		return uuid.Nil, nil
	}

	// get public key from certificate
	certificate, err := x509.ParseCertificate(cert.RawData)
	if err != nil {
		log.Errorf("%s: parsing x509 certificate failed: %v", errPrefix, err)
		return uuid.Nil, nil
	}

	pubKeyPEM, err := s.encPubKey(certificate.PublicKey)
	if err != nil {
		// this probably means that the certificate belongs to a public key
		// of an unsupported algorithm i.e. does not match a known key
		s.logCertMismatch("failed to parse public key from X.509 public key certificate with KID %s: %v", skidString, err)
		return uuid.Nil, nil
	}

	// look up matching UUID for public key
	uid, err := s.lookupUuid(pubKeyPEM)
	if err != nil {
		if err == ErrNotExist {
			s.logCertMismatch("unknown X.509 public key certificate found in trustList (dscg server): no registered identity has a public key that matches X.509 certificate with KID %s", skidString)
		} else {
			log.Errorf("%s: public key lookup failed: %v", errPrefix, err)
		}
		return uuid.Nil, nil
	}
	log.Debugf("%s: public key match: %s", skidString, uid)

	return uid, &skidCtx{
		SKID:      cert.Kid,
		NotBefore: certificate.NotBefore,
		NotAfter:  certificate.NotAfter,
	}
}

func (s *SkidHandler) checkCertificateValidity(uid uuid.UUID, skid *skidCtx, skidStore *map[uuid.UUID]skidCtx) {
	skidString := base64.StdEncoding.EncodeToString(skid.SKID)
	now := time.Now()

	if now.After(skid.NotAfter) {
		log.Debugf("X.509 public key certificate with KID %s expired: valid until %s", skidString, skid.NotAfter.Format(timeLayout))
		skid.expired = true
	} else if now.Before(skid.NotBefore) {
		log.Debugf("X.509 public key certificate with KID %s is not yet valid: valid from %s", skidString, skid.NotBefore.Format(timeLayout))
	} else {
		skid.Valid = true
	}

	if previouslyMatchedSkid, ok := (*skidStore)[uid]; ok {
		if previouslyMatchedSkid.Valid && !skid.Valid {
			return
		}

		// if the certificates are both valid or invalid, use the newer one, i.e. the one that starts being valid at a later time
		if (previouslyMatchedSkid.Valid && skid.Valid) || (!previouslyMatchedSkid.Valid && !skid.Valid) {
			if skid.NotBefore.Before(previouslyMatchedSkid.NotBefore) {
				return
			}
		}
	}

	(*skidStore)[uid] = *skid
}

func (s *SkidHandler) setSkidStore(newSkidStore map[uuid.UUID]skidCtx) {
	s.skidStoreMutex.Lock()
	s.skidStore = newSkidStore
	s.skidStoreMutex.Unlock()
}

func (s *SkidHandler) resetSkidStore() {
	s.setSkidStore(nil)
}

func (s *SkidHandler) updateSkidStore(newSkidStore map[uuid.UUID]skidCtx) {
	prevSKIDs, _ := json.Marshal(s.skidStore)
	newSKIDs, _ := json.Marshal(newSkidStore)

	s.setSkidStore(newSkidStore)

	if !bytes.Equal(prevSKIDs, newSKIDs) {
		if len(newSkidStore) == 0 {
			log.Warnf("no matching X.509 public key certificates found in trustList (dscg server)")
			return
		}

		invalidSKIDs := getInvalidSKIDs(newSkidStore)
		invalidSKIDsString, _ := json.Marshal(invalidSKIDs)

		log.Infof("loaded %d matching X.509 public key certificates from trustList (%d invalid): %s", len(newSkidStore), len(invalidSKIDs), newSKIDs)

		if len(invalidSKIDs) != 0 {
			log.Warnf("there are %d invalid X.509 public key certificates in the trustList (dscg server): %s", len(invalidSKIDs), invalidSKIDsString)
		}
	}
}

func getInvalidSKIDs(skidStore map[uuid.UUID]skidCtx) (invalidSKIDs map[uuid.UUID][]byte) {
	invalidSKIDs = make(map[uuid.UUID][]byte)
	for uid, skid := range skidStore {
		if !skid.Valid {
			invalidSKIDs[uid] = skid.SKID
		}
	}
	return invalidSKIDs
}

func (s *SkidHandler) GetSKID(uid uuid.UUID) ([]byte, string, error) {
	s.skidStoreMutex.RLock()
	skid, exists := s.skidStore[uid]
	s.skidStoreMutex.RUnlock()

	if !exists {
		if !s.isCertServerAvailable.Load().(bool) {
			errMsg := fmt.Sprintf("%v: trustList could not be loaded for %s",
				ErrCertServerNotAvailable, time.Duration(s.certLoadFailCounter)*s.certLoadInterval)
			return nil, errMsg, ErrCertServerNotAvailable
		}

		errMsg := fmt.Sprintf("seal with ID %s can not be used for signing: SKID unknown: %v", uid, ErrCertNotFound)
		return nil, errMsg, ErrCertNotFound
	}

	if !skid.Valid {
		errMsg := fmt.Sprintf("seal with ID %s can not be used for signing: %v", uid, ErrCertNotValid)
		if skid.expired {
			errMsg = fmt.Sprintf("%s: certificate expired, was valid until %s", errMsg, skid.NotAfter.Format(timeLayout))
		} else {
			errMsg = fmt.Sprintf("%s: certificate not yet valid, will be valid from %s", errMsg, skid.NotBefore.Format(timeLayout))
		}
		return nil, errMsg, ErrCertNotValid
	}

	return skid.SKID, "", nil
}
