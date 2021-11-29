package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var (
	ErrNotExist = errors.New("entry does not exist")
)

type StorageManager interface {
	StartTransaction(context.Context) (TransactionCtx, error)

	StoreIdentity(TransactionCtx, Identity) error
	LoadIdentity(uuid.UUID) (*Identity, error)

	GetUuidForPublicKey([]byte) (uuid.UUID, error)

	StoreAuth(TransactionCtx, uuid.UUID, string) error
	LoadAuthForUpdate(TransactionCtx, uuid.UUID) (string, error)

	IsReady() error
	Close()
}

type TransactionCtx interface {
	Commit() error
	Rollback() error
}

func GetStorageManager(c *Config) (StorageManager, error) {
	if len(c.PostgresDSN) != 0 {
		return NewSqlDatabaseInfo(c.PostgresDSN, PostgreSqlIdentityTableName, c.dbParams)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version")
	}
}
