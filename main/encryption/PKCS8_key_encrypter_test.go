package encrypters

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

func TestNewPKCS8KeyEncrypter(t *testing.T) {
	cryptoCtx := &ubirch.ECDSACryptoContext{}

	secret := make([]byte, 32)
	rand.Read(secret)

	enc, err := NewPKCS8KeyEncrypter(secret, cryptoCtx)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := cryptoCtx.GenerateKey()
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
