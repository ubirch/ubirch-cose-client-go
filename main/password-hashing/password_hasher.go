package password_hashing

import (
	"database/sql/driver"
	"encoding/base64"
	"fmt"
)

type PasswordHasher interface {
	DefaultParams() PasswordHashingParams
	GetPasswordHash(pw []byte, params PasswordHashingParams) (Password, error)
	CheckPasswordHash(pwToCheck []byte, pwHash Password) (bool, error)
}

type Password struct {
	AlgoID string
	Hash   Bytes
	Salt   Bytes
	Params PasswordHashingParams
}

type Bytes []byte
type PasswordHashingParams []byte

func (b *Bytes) Scan(src interface{}) error {
	var (
		err error
	)

	switch src := src.(type) {
	case nil:
	case string:
		*b, err = base64.StdEncoding.DecodeString(src)
	case []byte:
		*b, err = base64.StdEncoding.DecodeString(string(src))
	default:
		return fmt.Errorf("unable to scan type %T into PasswordSalt", src)
	}

	return err
}

func (b *Bytes) Value() (driver.Value, error) {
	return base64.StdEncoding.EncodeToString(*b), nil
}

func (p *PasswordHashingParams) Scan(src interface{}) error {
	switch src := src.(type) {
	case nil:
	case string:
		*p = []byte(src)
	case []byte:
		*p = src
	default:
		return fmt.Errorf("unable to scan type %T into PasswordHashingParams", src)
	}

	return nil
}

func (p *PasswordHashingParams) Value() (driver.Value, error) {
	return []byte(*p), nil
}
