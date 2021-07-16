package password_hashing

import (
	"fmt"
	"math/rand"
	"testing"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestScryptKeyDerivator_HashPassword(t *testing.T) {
	kd := NewDefaultScryptKeyDerivator()
	derivedKey := kd.HashPassword([]byte(test.Auth), []byte(test.Salt))

	if len(derivedKey) != kd.keyLen {
		t.Errorf("unexpected derived key length: %d, expected: %d", len(derivedKey), kd.keyLen)
	}
}

func BenchmarkScryptKeyDerivator_HashPassword_Default(b *testing.B) {
	kd := NewDefaultScryptKeyDerivator()
	b.Log(scryptParams(kd))

	auth := make([]byte, 32)
	rand.Read(auth)

	salt := make([]byte, 32)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kd.HashPassword(auth, salt)
	}
}

func BenchmarkScryptKeyDerivator_HashPassword_TweakParams(b *testing.B) {
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
		kd.HashPassword(auth, salt)
	}
}

func scryptParams(kd *ScryptKeyDerivator) string {
	return fmt.Sprintf(""+
		"\tN: %d MB"+
		"\t\tr: %d"+
		"\t\tp: %d"+
		"\t\tkeyLen: %d", kd.N/1024, kd.r, kd.p, kd.keyLen)
}
