package password_hashing

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"testing"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestScryptKeyDerivator(t *testing.T) {
	kd := ScryptKeyDerivator{}

	params, ok := kd.DefaultParams().(*Argon2idParams)
	if !ok {
		t.Fatal("invalid parameters")
	}

	pw, err := kd.GetPasswordHash(test.Auth, params)
	if err != nil {
		t.Fatal(err)
	}

	if len(pw.Hash) != int(params.KeyLen) {
		t.Errorf("unexpected derived key length: %d, expected: %d", len(pw.Hash), params.KeyLen)
	}
}

func TestScryptKeyDerivator_NotEqual(t *testing.T) {
	kd := &ScryptKeyDerivator{}

	params, ok := kd.DefaultParams().(*Argon2idParams)
	if !ok {
		t.Fatal("invalid parameters")
	}

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

func BenchmarkScryptKeyDerivator_Default(b *testing.B) {
	kd := &ScryptKeyDerivator{}

	params, ok := kd.DefaultParams().(*ScryptParams)
	if !ok {
		b.Fatal("invalid parameters")
	}
	b.Log(scryptParams(params))

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

func BenchmarkScryptKeyDerivator_TweakParams(b *testing.B) {
	kd := &ScryptKeyDerivator{}

	params := &ScryptParams{
		N:      16 * 1024,
		R:      8,
		P:      1,
		KeyLen: 24,
	}
	b.Log(scryptParams(params))

	auth := make([]byte, 32)
	rand.Read(auth)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kd.GetPasswordHash(base64.StdEncoding.EncodeToString(auth), params)
		if err != nil {
			b.Log(err)
		}
	}
}

func scryptParams(p *ScryptParams) string {
	return fmt.Sprintf(""+
		"\tN: %d MB"+
		"\t\tr: %d"+
		"\t\tp: %d"+
		"\t\tkeyLen: %d", p.N/1024, p.R, p.P, p.KeyLen)
}
