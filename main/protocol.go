// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const (
	SkidLen           = 8
	maxDbConnAttempts = 5
)

var (
	certLoadInterval     time.Duration
	maxCertLoadFailCount int
)

func setInterval(reloadEveryMinute bool) {
	if reloadEveryMinute {
		certLoadInterval = time.Minute
		maxCertLoadFailCount = 60
	} else {
		certLoadInterval = time.Hour
		maxCertLoadFailCount = 3
	}
}

type Protocol struct {
	ubirch.Crypto
	*Client
	ctxManager ContextManager

	identityCache *sync.Map // {<uid>: <*identity>}
	uidCache      *sync.Map // {<pub>: <uid>}

	skidStore           map[uuid.UUID][]byte
	skidStoreMutex      *sync.RWMutex
	certLoadFailCounter int
}

// Ensure Protocol implements the ContextManager interface
var _ ContextManager = (*Protocol)(nil)

func NewProtocol(ctxManager ContextManager, client *Client, reloadCertsEveryMinute bool) (*Protocol, error) {
	crypto := &ubirch.ECDSAPKCS11CryptoContext{}

	p := &Protocol{
		Crypto:     crypto,
		Client:     client,
		ctxManager: ctxManager,

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},

		skidStore:      map[uuid.UUID][]byte{},
		skidStoreMutex: &sync.RWMutex{},
	}

	// load public key certificate list from server and check for new certificates frequently
	go func() {
		setInterval(reloadCertsEveryMinute)

		p.loadSKIDs()
		for range time.Tick(certLoadInterval) {
			p.loadSKIDs()
		}
	}()

	return p, nil
}

func (p *Protocol) Close() {
	p.ctxManager.Close()
}

func (p *Protocol) StoreNewIdentity(id Identity) error {
	err := p.checkIdentityAttributesNotNil(&id)
	if err != nil {
		return err
	}

	for i := 0; i < maxDbConnAttempts; i++ {
		err = p.ctxManager.StoreNewIdentity(id)
		if err != nil && isConnectionNotAvailable(err) {
			log.Debugf("StoreNewIdentity connectionNotAvailable (%d of %d): %s", i+1, maxDbConnAttempts, err.Error())
			continue
		}
		break
	}
	return err
}

func (p *Protocol) GetIdentity(uid uuid.UUID) (id *Identity, err error) {
	_id, found := p.identityCache.Load(uid)

	if found {
		id, found = _id.(*Identity)
	}

	if !found {
		id, err = p.fetchIdentityFromStorage(uid)
		if err != nil {
			return nil, err
		}

		p.identityCache.Store(uid, id)
	}

	return id, nil
}

func (p *Protocol) fetchIdentityFromStorage(uid uuid.UUID) (id *Identity, err error) {
	for i := 0; i < maxDbConnAttempts; i++ {
		id, err = p.ctxManager.GetIdentity(uid)
		if err != nil && isConnectionNotAvailable(err) {
			log.Debugf("GetIdentity connectionNotAvailable (%d of %d): %s", i+1, maxDbConnAttempts, err.Error())
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}

	err = p.checkIdentityAttributesNotNil(id)
	if err != nil {
		return nil, err
	}

	return id, nil
}

func (p *Protocol) GetUuidForPublicKey(publicKeyPEM []byte) (uid uuid.UUID, err error) {
	sum256 := sha256.Sum256(publicKeyPEM)
	pubKeyID := base64.StdEncoding.EncodeToString(sum256[:16])

	_uid, found := p.uidCache.Load(pubKeyID)

	if found {
		uid, found = _uid.(uuid.UUID)
	}

	if !found {
		uid, err = p.fetchUuidForPublicKeyFromStorage(publicKeyPEM)
		if err != nil {
			return uuid.Nil, err
		}

		p.uidCache.Store(pubKeyID, uid)
	}

	return uid, nil
}

func (p *Protocol) fetchUuidForPublicKeyFromStorage(publicKeyBytes []byte) (uid uuid.UUID, err error) {
	for i := 0; i < maxDbConnAttempts; i++ {
		uid, err = p.ctxManager.GetUuidForPublicKey(publicKeyBytes)
		if err != nil && isConnectionNotAvailable(err) {
			log.Debugf("GetUuidForPublicKey connectionNotAvailable (%d of %d): %s", i+1, maxDbConnAttempts, err.Error())
			continue
		}
		break
	}
	return uid, err
}

func (p *Protocol) Exists(uid uuid.UUID) (exists bool, err error) {
	_, err = p.GetIdentity(uid)
	if err == ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (p *Protocol) checkIdentityAttributesNotNil(i *Identity) error {
	if i.Uid == uuid.Nil {
		return fmt.Errorf("uuid has Nil value: %s", i.Uid)
	}

	if len(i.PublicKey) == 0 {
		return fmt.Errorf("empty public key")
	}

	if len(i.AuthToken) == 0 {
		return fmt.Errorf("empty auth token")
	}

	return nil
}

func (p *Protocol) GetSKID(uid uuid.UUID) ([]byte, error) {
	p.skidStoreMutex.RLock()
	skid, exists := p.skidStore[uid]
	p.skidStoreMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("SKID unknown for identity %s (missing X.509 public key certificate)", uid)
	}

	return skid, nil
}

func (p *Protocol) setSkidStore(newSkidStore map[uuid.UUID][]byte) {
	p.skidStoreMutex.Lock()
	p.skidStore = newSkidStore
	p.skidStoreMutex.Unlock()
}

func (p *Protocol) loadSKIDs() {
	certs, err := p.RequestCertificateList()
	if err != nil {
		log.Error(err)

		p.certLoadFailCounter++
		log.Debugf("loading certificate list failed %d times,"+
			" clearing local KID lookup after %d failed attempts",
			p.certLoadFailCounter, maxCertLoadFailCount)

		// if we have not yet reached the maximum amount of failed attempts to load the certificate list,
		// return and try again later
		if p.certLoadFailCounter != maxCertLoadFailCount {
			return
		}

		// if we have reached the maximum amount of failed attempts to load the certificate list,
		// clear the SKID lookup
		log.Warnf("clearing local KID lookup after %d failed attempts to load public key certificate list",
			p.certLoadFailCounter)
	} else {
		// reset fail counter if certs were loaded successfully
		p.certLoadFailCounter = 0
	}

	tempSkidStore := map[uuid.UUID][]byte{}

	// go through certificate list and match known public keys
	for _, cert := range certs {
		kid := base64.StdEncoding.EncodeToString(cert.Kid)

		// get public key from certificate
		certificate, err := x509.ParseCertificate(cert.RawData)
		if err != nil {
			log.Errorf("%s: %v", kid, err)
			continue
		}

		pubKeyPEM, err := p.Crypto.EncodePublicKey(certificate.PublicKey)
		if err != nil {
			//log.Debugf("%s: unable to encode public key: %v", kid, err)
			continue
		}

		// look up matching UUID for public key
		uid, err := p.GetUuidForPublicKey(pubKeyPEM)
		if err != nil {
			if err != ErrNotExist {
				log.Errorf("%s: %v", kid, err)
			}
			continue
		}
		//log.Debugf("%s: public key certificate match", kid)

		if len(cert.Kid) != SkidLen {
			log.Errorf("invalid KID length: expected %d, got %d", SkidLen, len(kid))
			continue
		}

		tempSkidStore[uid] = cert.Kid
	}

	p.setSkidStore(tempSkidStore)

	skids, _ := json.Marshal(tempSkidStore)
	log.Infof("loaded %d matching certificates from server: %s", len(tempSkidStore), skids)
}
