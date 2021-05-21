package main

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

type LegacyFileManager struct {
	keyFile           string
	EncryptedKeystore *ubirch.EncryptedKeystore
	keystoreMutex     *sync.RWMutex
}

func NewLegacyFileManager(configDir string, secret []byte) (*LegacyFileManager, error) {
	f := &LegacyFileManager{
		keyFile:           filepath.Join(configDir, keyFileName),
		EncryptedKeystore: ubirch.NewEncryptedKeystore(secret),
		keystoreMutex:     &sync.RWMutex{},
	}

	log.Debugf(" - keystore file: %s", f.keyFile)

	err := f.portLegacyKeystoreFile()
	if err != nil {
		return nil, err
	}

	err = f.loadKeys()
	if err != nil {
		return nil, err
	}

	ids, err := f.EncryptedKeystore.GetIDs()
	if err != nil {
		return nil, err
	}
	log.Debugf("loaded %d existing keys from local file system", len(ids))

	return f, nil
}

func (f *LegacyFileManager) Exists(uid uuid.UUID) (bool, error) {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	_, err := f.EncryptedKeystore.GetPrivateKey(uid)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (f *LegacyFileManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	return f.EncryptedKeystore.GetPrivateKey(uid)
}

func (f *LegacyFileManager) SetPrivateKey(uid uuid.UUID, key []byte) error {
	f.keystoreMutex.Lock()
	defer f.keystoreMutex.Unlock()

	return f.EncryptedKeystore.SetPrivateKey(uid, key)
}

func (f *LegacyFileManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	return f.EncryptedKeystore.GetPublicKey(uid)
}

func (f *LegacyFileManager) SetPublicKey(uid uuid.UUID, key []byte) error {
	f.keystoreMutex.Lock()
	defer f.keystoreMutex.Unlock()

	return f.EncryptedKeystore.SetPublicKey(uid, key)
}

func (f *LegacyFileManager) loadKeys() error {
	return loadFile(f.keyFile, f.EncryptedKeystore.Keystore)
}

func (f *LegacyFileManager) persistKeys() error {
	return persistFile(f.keyFile, f.EncryptedKeystore.Keystore)
}

// this is here only for the purpose of backwards compatibility TODO: DEPRECATE
type legacyCryptoCtx struct {
	Keystore map[string]string
}

func (f *LegacyFileManager) portLegacyKeystoreFile() error {
	legacyKeystoreFile := &legacyCryptoCtx{Keystore: map[string]string{}}

	// read legacy protocol context from persistent storage
	err := loadFile(f.keyFile, legacyKeystoreFile)
	if err != nil {
		return fmt.Errorf("unable to load legacy protocol context: %v", err)
	}

	if len(legacyKeystoreFile.Keystore) == 0 {
		return nil
	}

	// persist loaded keys to new key storage
	err = persistFile(f.keyFile, legacyKeystoreFile.Keystore)
	if err != nil {
		return fmt.Errorf("unable to persist keys: %v", err)
	}

	return nil
}
