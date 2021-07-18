package password_hashing

import (
	"bytes"
	"crypto/rand"
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
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

var _ PasswordHashingParams = (*Argon2idParams)(nil)

func (kd *Argon2idKeyDerivator) DefaultParams() PasswordHashingParams {
	return &Argon2idParams{
		Time:    1,         // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03#section-9.3
		Memory:  64 * 1024, // 64 MB
		Threads: 4,
		KeyLen:  24,
	}
}

// GetPasswordHash derives a key from the password, salt, and cost parameters using Argon2id
// returning the derived key of length kd.keyLen
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03
func (kd *Argon2idKeyDerivator) GetPasswordHash(pw []byte, params PasswordHashingParams) (Password, error) {
	p, ok := params.(*Argon2idParams)
	if !ok {
		return Password{}, fmt.Errorf("invalid parameters")
	}

	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return Password{}, err
	}

	dk := argon2.IDKey(pw, salt, p.Time, p.Memory, p.Threads, p.KeyLen)

	return Password{
		AlgoID: Argon2idAlgID,
		Hash:   dk,
		Salt:   salt,
		Params: p,
	}, nil
}

func (kd *Argon2idKeyDerivator) CheckPasswordHash(pwToCheck []byte, pwHash Password) (bool, error) {
	if pwHash.AlgoID != Argon2idAlgID {
		return false, fmt.Errorf("unexpected algoID: %s, expected: %s", pwHash.AlgoID, Argon2idAlgID)
	}

	p, ok := pwHash.Params.(*Argon2idParams)
	if !ok {
		return false, fmt.Errorf("invalid parameters")
	}

	dk := argon2.IDKey([]byte(pwToCheck), pwHash.Salt, p.Time, p.Memory, p.Threads, p.KeyLen)

	return bytes.Equal(dk, pwHash.Hash), nil
}

func (p *Argon2idParams) Scan(src interface{}) error {
	switch src := src.(type) {
	case nil:
		return nil
	case string:
		return json.Unmarshal([]byte(src), p)
	case []byte:
		return json.Unmarshal(src, p)
	default:
		return fmt.Errorf("Scan: unable to scan type %T into Argon2idParams", src)
	}
}

func (p *Argon2idParams) Value() (driver.Value, error) {
	return json.Marshal(p)
}
