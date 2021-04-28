package main

import (
	"fmt"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"github.com/youmark/pkcs8"
)

type KeyEncrypter struct {
	Secret []byte
	Crypto ubirch.Crypto
}

func NewKeyEncrypter(secret []byte) (*KeyEncrypter, error) {
	if len(secret) != 32 {
		return nil, fmt.Errorf("secret length for AES-256 encryption must be 32 bytes (is %d)", len(secret))
	}
	return &KeyEncrypter{
		Secret: secret,
	}, nil
}

// Encrypt takes a PEM-encoded private key, AES256-encrypts it using the provided secret and
// returns the DER-encoded PKCS#8 private key
func (enc *KeyEncrypter) Encrypt(privateKeyPem []byte) ([]byte, error) {
	privateKey, err := enc.Crypto.DecodePrivateKey(privateKeyPem)
	if err != nil {
		return nil, err
	}
	return pkcs8.ConvertPrivateKeyToPKCS8(privateKey, enc.Secret)
}

func (enc *KeyEncrypter) Decrypt(encryptedPrivateKey []byte) (privateKeyPem []byte, err error) {
	privateKey, err := pkcs8.ParsePKCS8PrivateKey(encryptedPrivateKey, enc.Secret)
	if err != nil {
		return nil, err
	}
	return enc.Crypto.EncodePrivateKey(privateKey)
}
