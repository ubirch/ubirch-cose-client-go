package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

const (
	Commit   = true
	Rollback = false
)

var (
	ErrExists   = errors.New("entry already exists")
	ErrNotExist = errors.New("entry does not exist")
)

type StorageManager interface {
	StartTransaction(ctx context.Context) (transactionCtx interface{}, err error)
	CloseTransaction(transactionCtx interface{}, commit bool) error

	StoreNewIdentity(transactionCtx interface{}, id Identity) error
	GetIdentity(uid uuid.UUID) (Identity, error)

	GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error)

	IsRecoverable(error) bool
	IsReady() error
	Close()
}

func GetStorageManager(c *Config) (StorageManager, error) {
	if len(c.PostgresDSN) != 0 {
		return NewSqlDatabaseInfo(c.PostgresDSN, PostgreSqlIdentityTableName, c.dbParams)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version")
	}
}
