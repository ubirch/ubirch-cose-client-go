package password_hashing

import (
	"bytes"
	"fmt"

	log "github.com/sirupsen/logrus"
)

const PseudoAlgID = "pseudo"

type PseudoPWHasher struct{}

var _ PasswordHasher = (*PseudoPWHasher)(nil)

type PseudoParams []byte

func (kd *PseudoPWHasher) DefaultParams() PasswordHashingParams {
	log.Warn("USING PSEUDO PW HASHER")
	return []byte("PseudoParams")
}

func (kd *PseudoPWHasher) GetPasswordHash(pw []byte, params PasswordHashingParams) (Password, error) {
	log.Warn("USING PSEUDO PW HASHER")

	p := &PseudoParams{}
	err := p.Decode(params)
	if err != nil {
		return Password{}, fmt.Errorf("failed to decode PasswordHashingParams: %v", err)
	}

	salt := make([]byte, 16)

	return Password{
		AlgoID: PseudoAlgID,
		Hash:   pw,
		Salt:   salt,
		Params: params,
	}, nil
}

func (kd *PseudoPWHasher) CheckPasswordHash(pwToCheck []byte, pwHash Password) (bool, error) {
	log.Warn("USING PSEUDO PW HASHER")

	if pwHash.AlgoID != PseudoAlgID {
		return false, fmt.Errorf("unexpected algoID: %s, expected: %s", pwHash.AlgoID, PseudoAlgID)
	}

	return bytes.Equal(pwToCheck, pwHash.Hash), nil
}

func (p *PseudoParams) Decode(params PasswordHashingParams) error {
	*p = []byte(params)
	return nil
}

func (p *PseudoParams) Encode() (params PasswordHashingParams, err error) {
	return []byte(*p), nil
}
