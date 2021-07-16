package password_hashing

import (
	"golang.org/x/crypto/scrypt"

	log "github.com/sirupsen/logrus"
)

type ScryptKeyDerivator struct {
	N, r, p, keyLen int
}

func NewDefaultScryptKeyDerivator() *ScryptKeyDerivator {
	// The recommended parameters for interactive logins as of 2017 are
	// N=32768, r=8 and p=1.
	return &ScryptKeyDerivator{
		N:      32 * 1024,
		r:      8,
		p:      1,
		keyLen: 24,
	}
}

// HashPassword derives a key from the password, salt, and cost parameters using Scrypt
// returning the derived key of length kd.keyLen
func (kd *ScryptKeyDerivator) HashPassword(password, salt []byte) []byte {
	dk, err := scrypt.Key(password, salt, kd.N, kd.r, kd.p, kd.keyLen)
	if err != nil {
		log.Errorf("scrypt key derivation error: %v", err)
	}
	return dk
}
