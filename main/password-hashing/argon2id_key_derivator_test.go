package password_hashing

import (
	"fmt"
	"math/rand"
	"testing"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestArgon2idKeyDerivator_HashPassword(t *testing.T) {
	kd := NewDefaultArgon2idKeyDerivator()
	pwHash := kd.HashPassword([]byte(test.Auth), []byte(test.Salt))

	if len(pwHash) != int(kd.keyLen) {
		t.Errorf("unexpected derived key length: %d, expected: %d", len(pwHash), kd.keyLen)
	}
}

func BenchmarkArgon2idKeyDerivator_HashPassword_Default(b *testing.B) {
	kd := NewDefaultArgon2idKeyDerivator()
	b.Log(argon2idParams(kd))

	auth := make([]byte, 32)
	rand.Read(auth)

	salt := make([]byte, 32)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kd.HashPassword(auth, salt)
	}
}

func BenchmarkArgon2idKeyDerivator_HashPassword_TweakParams(b *testing.B) {
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
		kd.HashPassword(auth, salt)
	}
}

func argon2idParams(kd *Argon2idKeyDerivator) string {
	return fmt.Sprintf(""+
		"\ttime: %d"+
		"\t\tmemory: %d MB"+
		"\t\tthreads: %d"+
		"\t\tkeyLen: %d", kd.time, kd.memory/1024, kd.threads, kd.keyLen)
}
