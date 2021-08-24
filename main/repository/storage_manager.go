package repository

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"github.com/ubirch/ubirch-cose-client-go/main/ent"
)

var (
	ErrExists   = errors.New("entry already exists")
	ErrNotExist = errors.New("entry does not exist")
)

type StorageManager interface {
	StoreNewIdentity(id ent.Identity) error
	GetIdentity(uid uuid.UUID) (ent.Identity, error)

	GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error)

	IsRecoverable(error) bool
	IsReady() error
	Close()
}

func GetStorageManager(c *config.Config) (StorageManager, error) {
	if len(c.PostgresDSN) != 0 {
		return NewSqlDatabaseInfo(c.PostgresDSN, PostgreSqlIdentityTableName, c.DbParams)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version")
	}
}
