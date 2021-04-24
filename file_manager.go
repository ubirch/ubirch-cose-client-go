package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const (
	keyFileName = "keys.json"
	filePerm    = 0644
)

type FileManager struct {
	keyFile           string
	EncryptedKeystore *ubirch.EncryptedKeystore
	keystoreMutex     *sync.RWMutex
}

// Ensure FileManager implements the ContextManager interface
var _ ContextManager = (*FileManager)(nil)

func NewFileManager(configDir string, secret []byte) (*FileManager, error) {
	f := &FileManager{
		keyFile:           filepath.Join(configDir, keyFileName),
		EncryptedKeystore: ubirch.NewEncryptedKeystore(secret),
		keystoreMutex:     &sync.RWMutex{},
	}

	log.Info("keys are stored in local file system")
	log.Debugf(" - keystore file: %s", f.keyFile)

	err := f.loadKeys()
	if err != nil {
		return nil, err
	}

	return f, nil
}

func (f *FileManager) StartTransaction(uid uuid.UUID) error {
	f.keystoreMutex.Lock()
	defer f.keystoreMutex.Unlock()

	return f.loadKeys()
}

func (f *FileManager) EndTransaction(uid uuid.UUID, success bool) error {
	f.keystoreMutex.Lock()
	defer f.keystoreMutex.Unlock()

	if success {
		return f.persistKeys()
	} else {
		return f.loadKeys()
	}
}

func (f *FileManager) Exists(uid uuid.UUID) bool {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	_, err := f.EncryptedKeystore.GetPrivateKey(uid)
	if err != nil {
		return false
	}
	return true
}

func (f *FileManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	return f.EncryptedKeystore.GetPrivateKey(uid)
}

func (f *FileManager) SetPrivateKey(uid uuid.UUID, key []byte) error {
	f.keystoreMutex.Lock()
	defer f.keystoreMutex.Unlock()

	return f.EncryptedKeystore.SetPrivateKey(uid, key)
}

func (f *FileManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	return f.EncryptedKeystore.GetPublicKey(uid)
}

func (f *FileManager) SetPublicKey(uid uuid.UUID, key []byte) error {
	f.keystoreMutex.Lock()
	defer f.keystoreMutex.Unlock()

	return f.EncryptedKeystore.SetPublicKey(uid, key)
}

func (f *FileManager) loadKeys() error {
	return loadFile(f.keyFile, f.EncryptedKeystore.Keystore)
}

func (f *FileManager) persistKeys() error {
	return persistFile(f.keyFile, f.EncryptedKeystore.Keystore)
}

func loadFile(file string, dest interface{}) error {
	if _, err := os.Stat(file); os.IsNotExist(err) { // if file does not exist yet, return right away
		return nil
	}
	contextBytes, err := ioutil.ReadFile(file)
	if err != nil {
		file = file + ".bck"
		contextBytes, err = ioutil.ReadFile(file)
		if err != nil {
			return err
		}
	}
	err = json.Unmarshal(contextBytes, dest)
	if err != nil {
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			return loadFile(file+".bck", dest)
		}
	}
	return nil
}

func persistFile(file string, source interface{}) error {
	if _, err := os.Stat(file); !os.IsNotExist(err) { // if file already exists, create a backup
		err = os.Rename(file, file+".bck")
		if err != nil {
			log.Warnf("unable to create backup file for %s: %v", file, err)
		}
	}
	contextBytes, _ := json.MarshalIndent(source, "", "  ")
	return ioutil.WriteFile(file, contextBytes, filePerm)
}
