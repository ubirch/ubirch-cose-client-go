package password_hashing

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/scrypt"

	log "github.com/sirupsen/logrus"
)

const ScryptAlgID = "scrypt"

type ScryptKeyDerivator struct{}

var _ PasswordHasher = (*ScryptKeyDerivator)(nil)

type ScryptParams struct {
	N, R, P, KeyLen int
}

func (kd *ScryptKeyDerivator) DefaultParams() PasswordHashingParams {
	// The recommended parameters for interactive logins as of 2017 are
	// N=32768, r=8 and p=1.
	p := &ScryptParams{
		N:      32 * 1024,
		R:      8,
		P:      1,
		KeyLen: 24,
	}

	params, err := p.Encode()
	if err != nil {
		log.Errorf("failed to encode default parameter: %v", err)
	}
	log.Debugf("scrypt key derivation with parameters %s", params)

	return params
}

// GetPasswordHash derives a key from the password, salt, and cost parameters using Scrypt
// returning the derived key of length kd.keyLen
func (kd *ScryptKeyDerivator) GetPasswordHash(pw []byte, params PasswordHashingParams) (Password, error) {
	p := &ScryptParams{}
	err := p.Decode(params)
	if err != nil {
		return Password{}, fmt.Errorf("failed to decode PasswordHashingParams: %v", err)
	}

	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		return Password{}, err
	}

	dk, err := scrypt.Key(pw, salt, p.N, p.R, p.P, p.KeyLen)
	if err != nil {
		return Password{}, fmt.Errorf("scrypt key derivation error: %v", err)
	}

	return Password{
		AlgoID: ScryptAlgID,
		Hash:   dk,
		Salt:   salt,
		Params: params,
	}, nil
}

func (kd *ScryptKeyDerivator) CheckPasswordHash(pwToCheck []byte, pwHash Password) (bool, error) {
	if pwHash.AlgoID != ScryptAlgID {
		return false, fmt.Errorf("unexpected algoID: %s, expected: %s", pwHash.AlgoID, ScryptAlgID)
	}

	p := &ScryptParams{}
	err := p.Decode(pwHash.Params)
	if err != nil {
		return false, fmt.Errorf("failed to decode PasswordHashingParams: %v", err)
	}

	dk, err := scrypt.Key(pwToCheck, pwHash.Salt, p.N, p.R, p.P, p.KeyLen)
	if err != nil {
		return false, fmt.Errorf("scrypt key derivation error: %v", err)
	}

	return bytes.Equal(dk, pwHash.Hash), nil
}

func (p *ScryptParams) Decode(params PasswordHashingParams) error {
	return json.Unmarshal(params, p)
}

func (p *ScryptParams) Encode() (params PasswordHashingParams, err error) {
	return json.Marshal(p)
}
