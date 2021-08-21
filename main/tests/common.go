package tests

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
)

const (
	PrivHex = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"                                                                 //"10a0bef246575ea219e15bffbb6704d2a58b0e4aa99f101f12f0b1ce7a143559"
	PubHex  = "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771" //"92bbd65d59aecbdf7b497fb4dcbdffa22833613868ddf35b44f5bd672496664a2cc1d228550ae36a1d0210a3b42620b634dc5d22ecde9e12f37d66eeedee3e6a"
)

var (
	Uuid = uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")

	Key, _    = hex.DecodeString(PrivHex)
	PubKey, _ = hex.DecodeString(PubHex)

	Auth = "password1234!"

	Error = errors.New("test error")

	Argon2idParams = &pw.Argon2idParams{Time: 1, Memory: 1, Threads: 1, KeyLen: 1}
)

type MockKeystorer struct {
	priv []byte
	pub  []byte
}

var _ ubirch.Keystorer = (*MockKeystorer)(nil)

func (m *MockKeystorer) GetIDs() ([]uuid.UUID, error) {
	panic("implement me")
}

func (m *MockKeystorer) PrivateKeyExists(id uuid.UUID) (bool, error) {
	if len(m.priv) == 0 {
		return false, nil
	}
	return true, nil
}

func (m *MockKeystorer) GetPrivateKey(id uuid.UUID) ([]byte, error) {
	if len(m.priv) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	return m.priv, nil
}

func (m *MockKeystorer) SetPrivateKey(id uuid.UUID, key []byte) error {
	m.priv = key
	return nil
}

func (m *MockKeystorer) PublicKeyExists(id uuid.UUID) (bool, error) {
	if len(m.pub) == 0 {
		return false, nil
	}
	return true, nil
}

func (m *MockKeystorer) GetPublicKey(id uuid.UUID) ([]byte, error) {
	if len(m.pub) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	return m.pub, nil
}

func (m *MockKeystorer) SetPublicKey(id uuid.UUID, key []byte) error {
	m.pub = key
	return nil
}
