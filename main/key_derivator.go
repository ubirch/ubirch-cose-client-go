package main

import (
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"

	log "github.com/sirupsen/logrus"
)

type KeyDerivator interface {
	GetDerivedKey(password, salt []byte) []byte
}

type Argon2idKeyDerivator struct {
	time    uint32 // the time parameter specifies the number of passes over the memory
	memory  uint32 // the memory parameter specifies the size of the memory in KiB
	threads uint8  // the threads parameter specifies the number of threads and can be adjusted to the numbers of available CPUs
	keyLen  uint32 // the length of the resulting derived key in byte
}

func NewDefaultArgon2idKeyDerivator() *Argon2idKeyDerivator {
	return &Argon2idKeyDerivator{
		time:    1,         // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03#section-9.3
		memory:  64 * 1024, // 64 MB
		threads: 4,
		keyLen:  24,
	}
}

// GetDerivedKey derives a key from the password, salt, and cost parameters using Argon2id
// returning the derived key of length kd.keyLen
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03
func (kd *Argon2idKeyDerivator) GetDerivedKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, kd.time, kd.memory, kd.threads, kd.keyLen)
}

type ScryptKeyDerivator struct {
	N, r, p, keyLen int
}

func NewDefaultScryptKeyDerivator() *ScryptKeyDerivator {
	// The recommended parameters for interactive logins as of 2017 are
	// N=32768, r=8 and p=1.
	return &ScryptKeyDerivator{
		N:      32 * 1024,
		r:      8,
		p:      1,
		keyLen: 24,
	}
}

// GetDerivedKey derives a key from the password, salt, and cost parameters using Scrypt
// returning the derived key of length kd.keyLen
func (kd *ScryptKeyDerivator) GetDerivedKey(password, salt []byte) []byte {
	dk, err := scrypt.Key(password, salt, kd.N, kd.r, kd.p, kd.keyLen)
	if err != nil {
		log.Errorf("scrypt key derivation error: %v", err)
	}
	return dk
}
