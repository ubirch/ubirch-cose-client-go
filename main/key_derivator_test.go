package main

import (
	log "github.com/sirupsen/logrus"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
	"math/rand"
	"testing"
)

func TestArgon2idKeyDerivator_GetDerivedKey(t *testing.T) {
	kd := NewDefaultArgon2idKeyDerivator()
	derivedKey := kd.GetDerivedKey([]byte(test.Auth), []byte(test.Salt))
	t.Logf("%x", derivedKey)

	if len(derivedKey) != int(kd.keyLen) {
		log.Errorf("unexpected derived key length: %d, expected: %d", len(derivedKey), kd.keyLen)
	}
}

func BenchmarkArgon2idKeyDerivator_GetDerivedKey(b *testing.B) {
	kd := NewDefaultArgon2idKeyDerivator()

	auth := make([]byte, 32)
	rand.Read(auth)

	salt := make([]byte, 32)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kd.GetDerivedKey(auth, salt)
	}
}

func BenchmarkArgon2idKeyDerivator_GetDerivedKey_TweakParams(b *testing.B) {
	kd := Argon2idKeyDerivator{
		time:    1,
		memory:  32 * 1024,
		threads: 4,
		keyLen:  24,
	}

	auth := make([]byte, 32)
	rand.Read(auth)

	salt := make([]byte, 32)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kd.GetDerivedKey(auth, salt)
	}
}

func TestScryptKeyDerivator_GetDerivedKey(t *testing.T) {
	kd := NewDefaultScryptKeyDerivator()
	derivedKey := kd.GetDerivedKey([]byte(test.Auth), []byte(test.Salt))
	t.Logf("%x", derivedKey)

	if len(derivedKey) != kd.keyLen {
		log.Errorf("unexpected derived key length: %d, expected: %d", len(derivedKey), kd.keyLen)
	}
}

func BenchmarkScryptKeyDerivator_GetDerivedKey(b *testing.B) {
	kd := NewDefaultScryptKeyDerivator()

	auth := make([]byte, 32)
	rand.Read(auth)

	salt := make([]byte, 32)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kd.GetDerivedKey(auth, salt)
	}
}

func BenchmarkScryptKeyDerivator_GetDerivedKey_TweakParams(b *testing.B) {
	kd := ScryptKeyDerivator{
		N:      16 * 1024,
		r:      8,
		p:      1,
		keyLen: 24,
	}

	auth := make([]byte, 32)
	rand.Read(auth)

	salt := make([]byte, 32)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kd.GetDerivedKey(auth, salt)
	}
}
