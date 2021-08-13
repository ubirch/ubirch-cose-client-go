package password_hashing

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"testing"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestArgon2idKeyDerivator(t *testing.T) {
	kd := &Argon2idKeyDerivator{}
	params := kd.DefaultParams()

	pw, err := kd.GeneratePasswordHash(context.Background(), test.Auth, params)
	if err != nil {
		t.Fatal(err)
	}

	decodedParams, salt, hash, err := decodePasswordHash(pw)
	if err != nil {
		t.Fatalf("failed to decode argon2id password hash: %v", err)
	}

	if len(hash) != int(params.KeyLen) {
		t.Errorf("unexpected derived key length: %d, expected: %d", len(hash), params.KeyLen)
	}

	if len(salt) != int(params.SaltLen) {
		t.Errorf("unexpected salt length: %d, expected: %d", len(salt), params.SaltLen)
	}

	if *decodedParams != *params {
		t.Errorf("unexpected decoded params: %v, expected: %v", *decodedParams, *params)
	}
}

func TestArgon2idKeyDerivator_NotEqual(t *testing.T) {
	kd := &Argon2idKeyDerivator{}
	params := kd.DefaultParams()

	pw1, err := kd.GeneratePasswordHash(context.Background(), test.Auth, params)
	if err != nil {
		t.Fatal(err)
	}

	pw2, err := kd.GeneratePasswordHash(context.Background(), test.Auth, params)
	if err != nil {
		t.Fatal(err)
	}

	_, _, hash1, err := decodePasswordHash(pw1)
	if err != nil {
		t.Fatalf("failed to decode argon2id password hash: %v", err)
	}

	_, _, hash2, err := decodePasswordHash(pw2)
	if err != nil {
		t.Fatalf("failed to decode argon2id password hash: %v", err)
	}

	if bytes.Equal(hash1, hash2) {
		t.Errorf("generated passwords are the same: no salt random")
	}
}

func BenchmarkArgon2idKeyDerivator_Default(b *testing.B) {
	kd := &Argon2idKeyDerivator{}
	params := kd.DefaultParams()
	b.Log(argon2idParams(params))

	auth := make([]byte, 32)
	rand.Read(auth)
	authBase64 := base64.StdEncoding.EncodeToString(auth)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kd.GeneratePasswordHash(context.Background(), authBase64, params)
		if err != nil {
			b.Log(err)
		}
	}
}

func BenchmarkArgon2idKeyDerivator_TweakParams(b *testing.B) {
	kd := &Argon2idKeyDerivator{}

	params := &Argon2idParams{
		Memory:  37 * 1024,
		Time:    1,
		Threads: 4,
		KeyLen:  24,
		SaltLen: 16,
	}
	b.Log(argon2idParams(params))

	auth := make([]byte, 32)
	rand.Read(auth)
	authBase64 := base64.StdEncoding.EncodeToString(auth)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kd.GeneratePasswordHash(context.Background(), authBase64, params)
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
		"\t\tkeyLen: %d"+
		"\t\tsaltLen: %d", params.Time, params.Memory/1024, params.Threads, params.KeyLen, params.SaltLen)
}
