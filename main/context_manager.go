package main

import (
	"errors"

	"github.com/google/uuid"
)

var (
	ErrExists = errors.New("entry already exists")
)

type ContextManager interface {
	Exists(uid uuid.UUID) bool

	GetPrivateKey(uid uuid.UUID) (privKey []byte, err error)
	SetPrivateKey(uid uuid.UUID, privKey []byte) error

	GetPublicKey(uid uuid.UUID) (pubKey []byte, err error)
	SetPublicKey(uid uuid.UUID, pubKey []byte) error
}
