package ent

import (
	"github.com/google/uuid"
)

type Identity struct {
	Uid          uuid.UUID
	PublicKeyPEM []byte
	Auth         string
}
