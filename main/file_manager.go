package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

const (
	keyFileName = "keys.json"
	filePerm    = 0644
)

type FileManager struct {
	keyFile       string
	keystore      map[string][]byte
	keystoreMutex *sync.RWMutex
}

// Ensure FileManager implements the ContextManager interface
//var _ ContextManager = (*FileManager)(nil)

func NewFileManager(configDir string) (*FileManager, error) {
	f := &FileManager{
		keyFile:       filepath.Join(configDir, keyFileName),
		keystore:      map[string][]byte{},
		keystoreMutex: &sync.RWMutex{},
	}

	log.Debugf("loading keystore file: %s", f.keyFile)
	err := f.loadKeys()
	if err != nil {
		return nil, err
	}

	return f, nil
}

func (f *FileManager) ExistsPrivateKey(uid uuid.UUID) bool {
	return f.exists(privateKeyEntryID(uid))
}

func (f *FileManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	return f.getKey(privateKeyEntryID(uid))
}

func (f *FileManager) SetPrivateKey(uid uuid.UUID, key []byte) error {
	return f.setKey(privateKeyEntryID(uid), key)
}

func (f *FileManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	return f.getKey(publicKeyEntryID(uid))
}

func (f *FileManager) SetPublicKey(uid uuid.UUID, key []byte) error {
	return f.setKey(publicKeyEntryID(uid), key)
}

func (f *FileManager) exists(entryID string) bool {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	_, exists := f.keystore[entryID]
	return exists
}

func (f *FileManager) getKey(entryID string) ([]byte, error) {
	f.keystoreMutex.RLock()
	defer f.keystoreMutex.RUnlock()

	key, found := f.keystore[entryID]
	if !found {
		return nil, fmt.Errorf("key not found")
	}

	return key, nil
}

func (f *FileManager) setKey(entryID string, key []byte) error {
	f.keystoreMutex.Lock()
	defer f.keystoreMutex.Unlock()

	f.keystore[entryID] = key

	return f.persistKeys()
}

func (f *FileManager) loadKeys() error {
	return loadFile(f.keyFile, &f.keystore)
}

func (f *FileManager) persistKeys() error {
	return persistFile(f.keyFile, &f.keystore)
}

func privateKeyEntryID(id uuid.UUID) string {
	return "_" + id.String()
}

func publicKeyEntryID(id uuid.UUID) string {
	return id.String()
}

func loadFile(file string, dest interface{}) error {
	if _, err := os.Stat(file); os.IsNotExist(err) { // if file does not exist yet, return right away
		log.Warnf("file \"%s\" not found", file)
		return nil
	}
	contextBytes, err := ioutil.ReadFile(file)
	if err != nil {
		log.Warnf("reading from file \"%s\" failed: %v", file, err)
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			bckFile := file + ".bck"
			log.Warnf("read from backup file \"%s\"", bckFile)
			contextBytes, err = ioutil.ReadFile(bckFile)
			if err != nil {
				return err
			}
		}
	}
	err = json.Unmarshal(contextBytes, dest)
	if err != nil {
		log.Warnf("loading file \"%s\" failed: %v", file, err)
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			bckFile := file + ".bck"
			log.Warnf("load backup file \"%s\"", bckFile)
			return loadFile(bckFile, dest)
		}
	}
	return nil
}

func persistFile(file string, source interface{}) error {
	if _, err := os.Stat(file); err == nil { // if file already exists, create a backup
		err = os.Rename(file, file+".bck")
		if err != nil {
			log.Warnf("unable to create backup file for %s: %v", file, err)
		}
	}
	contextBytes, err := json.MarshalIndent(source, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, contextBytes, filePerm)
}
