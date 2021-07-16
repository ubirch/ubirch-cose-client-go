package password_hashing

type PasswordHasher interface {
	HashPassword(password, salt []byte) []byte
}

type Password struct {
	AlgoID string
	Hash   []byte
	Salt   []byte
	Params PasswordHashingParams
}

type PasswordHashingParams interface {
	Encode(interface{}) ([]byte, error)
	Decode([]byte) (interface{}, error)
}
