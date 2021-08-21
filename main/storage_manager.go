package main

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var (
	ErrExists   = errors.New("entry already exists")
	ErrNotExist = errors.New("entry does not exist")
)

type StorageManager interface {
	StoreNewIdentity(id Identity) error
	GetIdentity(uid uuid.UUID) (Identity, error)

	GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error)

	IsRecoverable(err error) bool
	Close()
}

func GetStorageManager(c *Config) (StorageManager, error) {
	if len(c.PostgresDSN) != 0 {
		return NewSqlDatabaseInfo(c.PostgresDSN, PostgreSqlIdentityTableName, c.dbParams)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version")
	}
}
