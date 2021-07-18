package password_hashing

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestScryptKeyDerivator(t *testing.T) {
	kd := ScryptKeyDerivator{}
	params := kd.DefaultParams()

	pw, err := kd.GetPasswordHash(test.Auth, params)
	if err != nil {
		t.Fatal(err)
	}

	p := &ScryptParams{}
	err = p.Decode(params)
	if err != nil {
		t.Fatal(err)
	}

	if len(pw.Hash) != int(p.KeyLen) {
		t.Errorf("unexpected derived key length: %d, expected: %d", len(pw.Hash), p.KeyLen)
	}
}

func TestScryptKeyDerivator_NotEqual(t *testing.T) {
	kd := &ScryptKeyDerivator{}
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

func BenchmarkScryptKeyDerivator_Default(b *testing.B) {
	kd := &ScryptKeyDerivator{}
	params := kd.DefaultParams()

	p := &ScryptParams{}
	err := p.Decode(params)
	if err != nil {
		b.Fatal(err)
	}
	b.Log(scryptParams(p))

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

	p := &ScryptParams{
		N:      16 * 1024,
		R:      8,
		P:      1,
		KeyLen: 24,
	}
	b.Log(scryptParams(p))

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

func scryptParams(p *ScryptParams) string {
	return fmt.Sprintf(""+
		"\tN: %d MB"+
		"\t\tr: %d"+
		"\t\tp: %d"+
		"\t\tkeyLen: %d", p.N/1024, p.R, p.P, p.KeyLen)
}
