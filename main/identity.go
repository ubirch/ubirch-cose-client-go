package main

import (
	"github.com/google/uuid"
)

type Identity struct {
	Uid          uuid.UUID `json:"uuid"`
	PublicKeyPEM []byte    `json:"publicKey"`
	Auth         string    `json:"auth"`
}
