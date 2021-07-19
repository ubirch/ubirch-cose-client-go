package main

import (
	"github.com/google/uuid"

	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
)

type Identity struct {
	Uid          uuid.UUID
	PublicKeyPEM []byte
	PW           pw.Password
}
