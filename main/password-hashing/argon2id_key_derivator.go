package password_hashing

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"

	log "github.com/sirupsen/logrus"
)

const Argon2idAlgID = "argon2id"

type Argon2idKeyDerivator struct{}

var _ PasswordHasher = (*Argon2idKeyDerivator)(nil)

type Argon2idParams struct {
	Time    uint32 // the time parameter specifies the number of passes over the memory
	Memory  uint32 // the memory parameter specifies the size of the memory in KiB
	Threads uint8  // the threads parameter specifies the number of threads and can be adjusted to the numbers of available CPUs
	KeyLen  uint32 // the length of the resulting derived key in byte
}

func (kd *Argon2idKeyDerivator) DefaultParams() PasswordHashingParams {
	p := &Argon2idParams{
		Time:    1,                           // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03#section-9.3
		Memory:  32 * 1024,                   // 32 MB
		Threads: uint8(runtime.NumCPU() * 2), // 2 * number of cores
		KeyLen:  24,
	}

	params, err := p.Encode()
	if err != nil {
		log.Errorf("failed to decode default parameter: %v", err)
	}
	log.Debugf("argon2id key derivation with parameters %s", params)

	return params
}

// GetPasswordHash derives a key from the password, salt, and cost parameters using Argon2id
// returning the derived key of length kd.keyLen
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03
func (kd *Argon2idKeyDerivator) GetPasswordHash(pw []byte, params PasswordHashingParams) (Password, error) {
	p := &Argon2idParams{}
	err := p.Decode(params)
	if err != nil {
		return Password{}, fmt.Errorf("failed to decode PasswordHashingParams: %v", err)
	}

	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		return Password{}, err
	}

	dk := argon2.IDKey(pw, salt, p.Time, p.Memory, p.Threads, p.KeyLen)

	return Password{
		AlgoID: Argon2idAlgID,
		Hash:   dk,
		Salt:   salt,
		Params: params,
	}, nil
}

func (kd *Argon2idKeyDerivator) CheckPasswordHash(pwToCheck []byte, pwHash Password) (bool, error) {
	if pwHash.AlgoID != Argon2idAlgID {
		return false, fmt.Errorf("unexpected algoID: %s, expected: %s", pwHash.AlgoID, Argon2idAlgID)
	}

	p := &Argon2idParams{}
	err := p.Decode(pwHash.Params)
	if err != nil {
		return false, fmt.Errorf("failed to decode PasswordHashingParams: %v", err)
	}

	dk := argon2.IDKey(pwToCheck, pwHash.Salt, p.Time, p.Memory, p.Threads, p.KeyLen)

	return bytes.Equal(dk, pwHash.Hash), nil
}

func (p *Argon2idParams) Decode(params PasswordHashingParams) error {
	return json.Unmarshal(params, p)
}

func (p *Argon2idParams) Encode() (params PasswordHashingParams, err error) {
	return json.Marshal(p)
}
