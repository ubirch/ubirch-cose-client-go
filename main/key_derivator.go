package main

import (
	"golang.org/x/crypto/argon2"
)

type KeyDerivator struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func NewDefaultKeyDerivator() *KeyDerivator {
	return &KeyDerivator{
		time:    1, // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03#section-9.3
		memory:  64 * 1024,
		threads: 4,
		keyLen:  24,
	}
}

// GetDerivedKey derives a key from the password, salt, and cost parameters using Argon2id
// returning the derived key of length kd.keyLen
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03
func (kd *KeyDerivator) GetDerivedKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, kd.time, kd.memory, kd.threads, kd.keyLen)
}