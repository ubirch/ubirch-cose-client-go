package main

import (
	"fmt"
	"math/rand"
	"testing"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestArgon2idKeyDerivator_GetDerivedKey(t *testing.T) {
	kd := NewDefaultArgon2idKeyDerivator()
	derivedKey := kd.GetDerivedKey([]byte(test.Auth), []byte(test.Salt))
	t.Logf("%x", derivedKey)

	if len(derivedKey) != int(kd.keyLen) {
		t.Errorf("unexpected derived key length: %d, expected: %d", len(derivedKey), kd.keyLen)
	}
}

func BenchmarkArgon2idKeyDerivator_GetDerivedKey_Default(b *testing.B) {
	kd := NewDefaultArgon2idKeyDerivator()
	b.Log(argon2idParams(kd))

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
	kd := &Argon2idKeyDerivator{
		time:    1,
		memory:  16 * 1024,
		threads: 2,
		keyLen:  24,
	}
	b.Log(argon2idParams(kd))

	auth := make([]byte, 32)
	rand.Read(auth)

	salt := make([]byte, 32)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kd.GetDerivedKey(auth, salt)
	}
}

func argon2idParams(kd *Argon2idKeyDerivator) string {
	return fmt.Sprintf(""+
		"\ttime: %d"+
		"\t\tmemory: %d MB"+
		"\t\tthreads: %d"+
		"\t\tkeyLen: %d", kd.time, kd.memory/1024, kd.threads, kd.keyLen)
}

func TestScryptKeyDerivator_GetDerivedKey(t *testing.T) {
	kd := NewDefaultScryptKeyDerivator()
	derivedKey := kd.GetDerivedKey([]byte(test.Auth), []byte(test.Salt))
	t.Logf("%x", derivedKey)

	if len(derivedKey) != kd.keyLen {
		t.Errorf("unexpected derived key length: %d, expected: %d", len(derivedKey), kd.keyLen)
	}
}

func BenchmarkScryptKeyDerivator_GetDerivedKey_Default(b *testing.B) {
	kd := NewDefaultScryptKeyDerivator()
	b.Log(scryptParams(kd))

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
	kd := &ScryptKeyDerivator{
		N:      16 * 1024,
		r:      8,
		p:      1,
		keyLen: 24,
	}
	b.Log(scryptParams(kd))

	auth := make([]byte, 32)
	rand.Read(auth)

	salt := make([]byte, 32)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kd.GetDerivedKey(auth, salt)
	}
}

func scryptParams(kd *ScryptKeyDerivator) string {
	return fmt.Sprintf(""+
		"\tN: %d MB"+
		"\t\tr: %d"+
		"\t\tp: %d"+
		"\t\tkeyLen: %d", kd.N/1024, kd.r, kd.p, kd.keyLen)
}
