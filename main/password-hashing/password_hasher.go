package password_hashing

import "database/sql/driver"

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

type PasswordHashingParams interface {
	Scan(src interface{}) error
	Value() (driver.Value, error)
}
