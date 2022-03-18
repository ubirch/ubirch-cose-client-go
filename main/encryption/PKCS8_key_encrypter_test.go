package encrypters

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

func TestNewPKCS8KeyEncrypter(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{Keystore: &MockKeystorer{}}

	secret := make([]byte, 32)
	rand.Read(secret)

	enc, err := NewPKCS8KeyEncrypter(secret, cryptoCtx)
	if err != nil {
		t.Fatal(err)
	}

	uid := uuid.New()

	err = cryptoCtx.GenerateKey(uid)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := cryptoCtx.Keystore.GetPrivateKey(uid)
	if err != nil {
		t.Fatal(err)
	}

	encryptedPriv, err := enc.Encrypt(priv)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(priv, encryptedPriv) {
		t.Error("private key was not encrypted")
	}

	decryptedPriv, err := enc.Decrypt(encryptedPriv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(priv, decryptedPriv) {
		t.Error("decrypted private key is not equal original private key")
	}
}

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
