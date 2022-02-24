package main

import (
	"github.com/google/uuid"
)

type Identity struct {
	Uid        uuid.UUID `json:"uuid"`
	PrivateKey []byte    `json:"privateKey"`
	PublicKey  []byte    `json:"publicKey"`
	Auth       string    `json:"auth"`
}
