package password_hashing

import (
	"database/sql/driver"
	"fmt"
)

type PasswordHasher interface {
	DefaultParams() PasswordHashingParams
	GetPasswordHash(pw []byte, params PasswordHashingParams) (Password, error)
	CheckPasswordHash(pwToCheck []byte, pwHash Password) (bool, error)
}

type Password struct {
	AlgoID string
	Hash   []byte
	Salt   []byte
	Params PasswordHashingParams
}

type PasswordHashingParams []byte

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
