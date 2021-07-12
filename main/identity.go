package main

import "github.com/google/uuid"

type Password struct {
	DerivedKey []byte
	Salt       []byte
}

type Identity struct {
	Uid          uuid.UUID
	PublicKeyPEM []byte
	PW           Password
}
