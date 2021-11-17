package password_hashing

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2idKeyDerivator(t *testing.T) {
	testAuth := generateRandomAuth()

	kd := NewArgon2idKeyDerivator(DefaultMemory)
	params := kd.DefaultParams()

	pw, err := kd.GeneratePasswordHash(context.Background(), testAuth, params)
	require.NoError(t, err)

	decodedParams, salt, hash, err := decodePasswordHash(pw)
	require.NoError(t, err)
	assert.Equal(t, int(params.KeyLen), len(hash))
	assert.Equal(t, int(params.SaltLen), len(salt))
	assert.Equal(t, *params, *decodedParams)

	ok, err := kd.CheckPassword(context.Background(), testAuth, pw)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestArgon2idKeyDerivator_NotEqual(t *testing.T) {
	testAuth := generateRandomAuth()

	kd := &Argon2idKeyDerivator{}
	params := kd.DefaultParams()

	pw1, err := kd.GeneratePasswordHash(context.Background(), testAuth, params)
	require.NoError(t, err)

	pw2, err := kd.GeneratePasswordHash(context.Background(), testAuth, params)
	require.NoError(t, err)

	_, _, hash1, err := decodePasswordHash(pw1)
	require.NoError(t, err)

	_, _, hash2, err := decodePasswordHash(pw2)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "generated passwords are the same: no salt random")
}

func TestDecode(t *testing.T) {
	testHash := []byte("hash......")
	testSalt := []byte("salt...")
	testParams := &Argon2idParams{
		Memory:  4 * 1024,
		Time:    2,
		Threads: 8,
		KeyLen:  uint32(len(testHash)),
		SaltLen: uint32(len(testSalt)),
	}

	encodedPasswordHash := encodePasswordHash(testParams, testSalt, testHash)

	params, salt, hash, err := decodePasswordHash(encodedPasswordHash)
	require.NoError(t, err)

	asserter := assert.New(t)
	asserter.Equal(params, testParams)
	asserter.Equal(salt, testSalt)
	asserter.Equal(hash, testHash)
}

func TestGetArgon2idParams(t *testing.T) {
	kd := &Argon2idKeyDerivator{}
	defaultParams := kd.DefaultParams()
	params := GetArgon2idParams(0, 0, 0, 0, 0)

	assert.Equal(t, *defaultParams, *params)
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

const concurrency = 8

func BenchmarkArgon2idKeyDerivator_Default_Concurrency(b *testing.B) {
	kd := &Argon2idKeyDerivator{}
	params := kd.DefaultParams()
	b.Log(concurrency)
	b.Log(argon2idParams(params))

	auth := make([]byte, 32)
	rand.Read(auth)
	authBase64 := base64.StdEncoding.EncodeToString(auth)

	wg := &sync.WaitGroup{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(concurrency)
		for n := 0; n < concurrency; n++ {
			go gen(wg, kd, authBase64, params)
		}
		wg.Wait()
	}
}

func gen(wg *sync.WaitGroup, kd *Argon2idKeyDerivator, authBase64 string, params *Argon2idParams) {
	defer wg.Done()
	_, err := kd.GeneratePasswordHash(context.Background(), authBase64, params)
	if err != nil {
		panic(err)
	}
}

func BenchmarkArgon2idKeyDerivator_TweakParams(b *testing.B) {
	memMiB := uint32(37)
	time := uint32(1)
	threads := uint8(4)

	kd := &Argon2idKeyDerivator{}
	params := GetArgon2idParams(memMiB, time, threads, DefaultKeyLen, DefaultSaltLen)
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

func generateRandomAuth() string {
	b := make([]byte, 32)
	rand.Read(b)

	return base64.RawStdEncoding.EncodeToString(b)
}
