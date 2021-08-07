package password_hashing

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sync/semaphore"
)

const stdEncodingFormat = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"

type Argon2idKeyDerivator struct {
	sem *semaphore.Weighted
}

type Argon2idParams struct {
	SaltLen uint32 // the length of the random salt in byte
	Time    uint32 // the time parameter specifies the number of passes over the memory
	Memory  uint32 // the memory parameter specifies the size of the memory in KiB
	Threads uint8  // the threads parameter specifies the number of threads and can be adjusted to the numbers of available CPUs
	KeyLen  uint32 // the length of the resulting derived key in byte
}

func (kd *Argon2idKeyDerivator) DefaultParams() *Argon2idParams {
	return &Argon2idParams{
		SaltLen: 16,
		Time:    1,                           // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03#section-9.3
		Memory:  32 * 1024,                   // 32 MB
		Threads: uint8(runtime.NumCPU() * 2), // 2 * number of cores
		KeyLen:  24,
	}
}

// GeneratePasswordHash derives a key from the password, salt, and cost parameters using Argon2id
// returning the standard encoded representation of the hashed password
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03
func (kd *Argon2idKeyDerivator) GeneratePasswordHash(pw string, params *Argon2idParams) (string, error) {
	salt := make([]byte, params.SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(pw), salt, params.Time, params.Memory, params.Threads, params.KeyLen)

	return encodePasswordHash(params, salt, hash), nil
}

func (kd *Argon2idKeyDerivator) CheckPassword(pwToCheck string, pwHash string) (bool, error) {
	p, salt, hash, err := decodePasswordHash(pwHash)
	if err != nil {
		return false, fmt.Errorf("failed to decode argon2id password hash: %v", err)
	}

	hashToCheck := argon2.IDKey([]byte(pwToCheck), salt, p.Time, p.Memory, p.Threads, p.KeyLen)

	return bytes.Equal(hash, hashToCheck), nil
}

func encodePasswordHash(params *Argon2idParams, salt, hash []byte) string {
	saltBase64 := base64.RawStdEncoding.EncodeToString(salt)
	hashBase64 := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(stdEncodingFormat, argon2.Version, params.Memory, params.Time, params.Threads, saltBase64, hashBase64)
}

func decodePasswordHash(encodedPasswordHash string) (params *Argon2idParams, salt, hash []byte, err error) {
	params = &Argon2idParams{}

	vals := strings.Split(encodedPasswordHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid encoded argon2id password hash: %s", encodedPasswordHash)
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("unsupported argon2id version: %d", version)
	}

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Time, &params.Threads)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.SaltLen = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.KeyLen = uint32(len(hash))

	return params, salt, hash, nil
}
