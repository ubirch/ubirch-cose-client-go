package main

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/config"
)

var (
	ErrExists = errors.New("entry already exists")
)

type ContextManager interface {
	ExistsPrivateKey(uid uuid.UUID) bool
	GetPrivateKey(uid uuid.UUID) (privKey []byte, err error)
	SetPrivateKey(uid uuid.UUID, privKey []byte) error

	ExistsPublicKey(uid uuid.UUID) bool
	GetPublicKey(uid uuid.UUID) (pubKey []byte, err error)
	SetPublicKey(uid uuid.UUID, pubKey []byte) error

	//ExistsSKID(uid uuid.UUID) bool
	//GetSKID(uid uuid.UUID) (skid []byte, err error)
	//SetSKID(uid uuid.UUID, skid []byte) error
}

func GetCtxManager(c config.Config) (ContextManager, error) {
	if c.DsnInitContainer {
		return NewSqlDatabaseInfo(c)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version")
	}
}
