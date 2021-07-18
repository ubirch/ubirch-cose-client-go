package password_hashing

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestArgon2idKeyDerivator(t *testing.T) {
	kd := &Argon2idKeyDerivator{}
	params := kd.DefaultParams()

	pw, err := kd.GetPasswordHash(test.Auth, params)
	if err != nil {
		t.Fatal(err)
	}

	p := &Argon2idParams{}
	err = p.Decode(params)
	if err != nil {
		t.Fatal(err)
	}

	if len(pw.Hash) != int(p.KeyLen) {
		t.Errorf("unexpected derived key length: %d, expected: %d", len(pw.Hash), p.KeyLen)
	}
}

func TestArgon2idKeyDerivator_NotEqual(t *testing.T) {
	kd := &Argon2idKeyDerivator{}
	params := kd.DefaultParams()

	pw1, err := kd.GetPasswordHash(test.Auth, params)
	if err != nil {
		t.Fatal(err)
	}

	pw2, err := kd.GetPasswordHash(test.Auth, params)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(pw1.Hash, pw2.Hash) {
		t.Errorf("generated passwords are the same: no salt random")
	}
}

func BenchmarkArgon2idKeyDerivator_Default(b *testing.B) {
	kd := &Argon2idKeyDerivator{}
	params := kd.DefaultParams()

	p := &Argon2idParams{}
	err := p.Decode(params)
	if err != nil {
		b.Fatal(err)
	}
	b.Log(argon2idParams(p))

	auth := make([]byte, 32)
	rand.Read(auth)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kd.GetPasswordHash(auth, params)
		if err != nil {
			b.Log(err)
		}
	}
}

func BenchmarkArgon2idKeyDerivator_TweakParams(b *testing.B) {
	kd := &Argon2idKeyDerivator{}

	p := &Argon2idParams{
		Time:    1,
		Memory:  16 * 1024,
		Threads: 2,
		KeyLen:  24,
	}
	b.Log(argon2idParams(p))

	params, err := p.Encode()
	if err != nil {
		b.Fatalf("failed to decode parameter: %v", err)
	}

	auth := make([]byte, 32)
	rand.Read(auth)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kd.GetPasswordHash(auth, params)
		if err != nil {
			b.Log(err)
		}
	}
}

func argon2idParams(params *Argon2idParams) string {
	return fmt.Sprintf(""+
		"\ttime: %d"+
		"\t\tmemory: %d MB"+
		"\t\tthreads: %d"+
		"\t\tkeyLen: %d", params.Time, params.Memory/1024, params.Threads, params.KeyLen)
}
