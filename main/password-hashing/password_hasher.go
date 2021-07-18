package password_hashing

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

type PasswordHashingParams map[string]interface{}
