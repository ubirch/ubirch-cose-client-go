package password_hashing

import (
	"bytes"
	"crypto/rand"
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const ScryptAlgID = "scrypt"

type ScryptKeyDerivator struct{}

var _ PasswordHasher = (*ScryptKeyDerivator)(nil)

type ScryptParams struct {
	N, R, P, KeyLen int
}

var _ PasswordHashingParams = (*ScryptParams)(nil)

func (kd *ScryptKeyDerivator) DefaultParams() PasswordHashingParams {
	// The recommended parameters for interactive logins as of 2017 are
	// N=32768, r=8 and p=1.
	return &ScryptParams{
		N:      32 * 1024,
		R:      8,
		P:      1,
		KeyLen: 24,
	}
}

// GetPasswordHash derives a key from the password, salt, and cost parameters using Scrypt
// returning the derived key of length kd.keyLen
func (kd *ScryptKeyDerivator) GetPasswordHash(pw []byte, params PasswordHashingParams) (Password, error) {
	p, ok := params.(*ScryptParams)
	if !ok {
		return Password{}, fmt.Errorf("invalid parameters")
	}

	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return Password{}, err
	}

	dk, err := scrypt.Key([]byte(pw), salt, p.N, p.R, p.P, p.KeyLen)
	if err != nil {
		return Password{}, fmt.Errorf("scrypt key derivation error: %v", err)
	}

	return Password{
		AlgoID: ScryptAlgID,
		Hash:   dk,
		Salt:   salt,
		Params: p,
	}, nil
}

func (kd *ScryptKeyDerivator) CheckPasswordHash(pwToCheck []byte, pwHash Password) (bool, error) {
	if pwHash.AlgoID != ScryptAlgID {
		return false, fmt.Errorf("unexpected algoID: %s, expected: %s", pwHash.AlgoID, ScryptAlgID)
	}

	p, ok := pwHash.Params.(*ScryptParams)
	if !ok {
		return false, fmt.Errorf("invalid parameters")
	}

	dk, err := scrypt.Key([]byte(pwToCheck), pwHash.Salt, p.N, p.R, p.P, p.KeyLen)
	if err != nil {
		return false, fmt.Errorf("scrypt key derivation error: %v", err)
	}

	return bytes.Equal(dk, pwHash.Hash), nil
}

func (p *ScryptParams) Scan(src interface{}) error {
	switch src := src.(type) {
	case nil:
		return nil
	case string:
		return json.Unmarshal([]byte(src), p)
	case []byte:
		return json.Unmarshal(src, p)
	default:
		return fmt.Errorf("Scan: unable to scan type %T into ScryptParams", src)
	}
}

func (p *ScryptParams) Value() (driver.Value, error) {
	return json.Marshal(p)
}
