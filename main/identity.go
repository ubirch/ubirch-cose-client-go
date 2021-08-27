package main

import (
	"github.com/google/uuid"
)

type Identity struct {
	Uid        uuid.UUID `json:"uuid"`
	PrivateKey []byte    `json:"privKey"`
	PublicKey  []byte    `json:"pubKey"`
	AuthToken  string    `json:"token"`
}
