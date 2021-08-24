package repository

import (
	"bytes"
	"github.com/ubirch/ubirch-cose-client-go/main/ent"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"

	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
)

func TestProtocol(t *testing.T) {
	testUid := uuid.New()

	cryptoCtx := &ubirch.ECDSACryptoContext{
		Keystore: &test.MockKeystorer{},
	}

	err := cryptoCtx.GenerateKey(testUid)
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM, err := cryptoCtx.GetPublicKeyPEM(testUid)
	if err != nil {
		t.Fatal(err)
	}

	p := &Protocol{
		StorageManager: &mockStorageMngr{},

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
	}

	testIdentity := ent.Identity{
		Uid:          testUid,
		PublicKeyPEM: pubKeyPEM,
		Auth:         test.Auth,
	}

	// check not exists
	_, err = p.GetIdentity(testIdentity.Uid)
	if err != ErrNotExist {
		t.Error("GetIdentity did not return ErrNotExist")
	}

	exists, err := p.isInitialized(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if exists {
		t.Error("isInitialized returned TRUE")
	}

	_, err = p.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
	if err != ErrNotExist {
		t.Error("GetUuidForPublicKey did not return ErrNotExist")
	}

	err = p.StoreNewIdentity(testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	// check exists
	exists, err = p.isInitialized(testIdentity.Uid)
	if err != nil {
		t.Error(err)
	}
	if !exists {
		t.Error("isInitialized returned FALSE")
	}

	storedIdentity, err := p.GetIdentity(testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(storedIdentity.Uid[:], testIdentity.Uid[:]) {
		t.Error("GetIdentity returned unexpected Uid value")
	}
	if !bytes.Equal(storedIdentity.PublicKeyPEM, testIdentity.PublicKeyPEM) {
		t.Error("GetIdentity returned unexpected PublicKeyPEM value")
	}
	if storedIdentity.Auth != testIdentity.Auth {
		t.Error("GetIdentity returned unexpected Auth value")
	}

	storedUid, err := p.GetUuidForPublicKey(testIdentity.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedUid[:], testIdentity.Uid[:]) {
		t.Errorf("GetUuidForPublicKey returned unexpected value: %s, expected: %s", storedUid[:], testIdentity.Uid[:])
	}
}

func TestProtocolLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUpDB(t, dm)

	p := &Protocol{
		StorageManager: dm,

		identityCache: &sync.Map{},
		uidCache:      &sync.Map{},
	}

	// generate identities
	var testIdentities []*ent.Identity
	for i := 0; i < testLoad/10; i++ {
		testId := generateRandomIdentity()

		testIdentities = append(testIdentities, testId)
	}

	// store identities
	for i, testId := range testIdentities {
		wg.Add(1)
		go func(idx int, identity *ent.Identity) {
			err := storeIdentity(p, identity, wg)
			if err != nil {
				t.Errorf("%s: identity could not be stored: %v", identity.Uid, err)
			}
		}(i, testId)
	}
	wg.Wait()

	// check identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(id *ent.Identity) {
			err := checkIdentity(p, id, wg)
			if err != nil {
				t.Errorf("%s: %v", id.Uid, err)
			}
		}(testId)
	}
	wg.Wait()
}

func Test_StoreNewIdentity_BadUUID(t *testing.T) {
	p := NewProtocol(&mockStorageMngr{}, 0, &pw.Argon2idParams{})

	i := ent.Identity{
		Uid:          uuid.UUID{},
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
	}

	err := p.StoreNewIdentity(i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid UUID")
	}
}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	p := NewProtocol(&mockStorageMngr{}, 0, &pw.Argon2idParams{})

	i := ent.Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: nil,
		Auth:         test.Auth,
	}

	err := p.StoreNewIdentity(i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid public key")
	}
}

func Test_StoreNewIdentity_NilAuth(t *testing.T) {
	p := NewProtocol(&mockStorageMngr{}, 0, &pw.Argon2idParams{})

	i := ent.Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         "",
	}

	err := p.StoreNewIdentity(i)
	if err == nil {
		t.Error("StoreNewIdentity did not return error for invalid auth token")
	}
}

func TestProtocol_Cache(t *testing.T) {
	wg := &sync.WaitGroup{}

	p := NewProtocol(&mockStorageMngr{}, 0, &pw.Argon2idParams{})

	testIdentity := ent.Identity{
		Uid:          test.Uuid,
		PublicKeyPEM: test.PubKey,
		Auth:         test.Auth,
	}

	err := p.StoreNewIdentity(testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	// repeatedly check same identity to test cache
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			err := checkIdentity(p, &testIdentity, wg)
			if err != nil {
				t.Errorf("%s: %v", testIdentity.Uid, err)
			}
		}()
	}
	wg.Wait()
}

func TestProtocol_GetUuidForPublicKey_BadPublicKey(t *testing.T) {
	p := NewProtocol(&mockStorageMngr{}, 0, &pw.Argon2idParams{})

	_, err := p.GetUuidForPublicKey(make([]byte, 64))
	if err == nil {
		t.Error("GetUuidForPublicKey did not return error for invalid public key")
	}
}

type mockStorageMngr struct {
	id ent.Identity
}

var _ StorageManager = (*mockStorageMngr)(nil)

func (m *mockStorageMngr) StoreNewIdentity(id ent.Identity) error {
	m.id = id
	return nil
}

func (m *mockStorageMngr) GetIdentity(uid uuid.UUID) (ent.Identity, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != uid {
		return ent.Identity{}, ErrNotExist
	}
	return m.id, nil
}

func (m *mockStorageMngr) GetUuidForPublicKey(pubKey []byte) (uuid.UUID, error) {
	if m.id.PublicKeyPEM == nil || !bytes.Equal(m.id.PublicKeyPEM, pubKey) {
		return uuid.Nil, ErrNotExist
	}
	return m.id.Uid, nil
}

func (m *mockStorageMngr) IsRecoverable(error) bool {
	return false
}

func (m *mockStorageMngr) IsReady() error {
	return nil
}

func (m *mockStorageMngr) Close() {}

//func TestProtocol_GetUuidForPublicKey_BadPublicKey(t *testing.T) {
//	cryptoCtx := &ubirch.ECDSACryptoContext{
//		Keystore: &test.MockKeystorer{},
//	}
//	by := make([]byte, 64)
//
//	ctrl := gomock.NewController(t)
//	defer ctrl.Finish()
//
//	mockCtxMngr := test.NewMockContextManager(ctrl)
//
//	mockCtxMngr.EXPECT().GetUuidForPublicKey(by).Times(1).Return(uuid.Nil, ErrNotExist)
//	p := NewProtocol(cryptoCtx, mockCtxMngr, 10, &pw.Argon2idParams{})
//	defer p.Close()
//
//	p.GetUuidForPublicKey(by)
//}
