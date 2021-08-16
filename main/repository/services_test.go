package repository

import (
	"bytes"
	"context"
	"encoding/hex"
	"github.com/ubirch/ubirch-cose-client-go/main/ent"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server/helper"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestCOSEServiceHandleRequest_HashRequest_Base64(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEServiceHandleRequest_HashRequest_Hex(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	testHashHex := "76e114443cd386716c0f8408ce99e0017d07e68fef22ade5b39966941b35881f"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHashHex))
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set("Content-Transfer-Encoding", HexEncoding)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEServiceHandleRequest_HashRequest_Bytes(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	testHashBytes, _ := hex.DecodeString("76e114443cd386716c0f8408ce99e0017d07e68fef22ade5b39966941b35881f")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(testHashBytes))
	r.Header.Set("Content-Type", h.BinType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEService_HandleRequest_BadUUID(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(GetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusNotFound)
	}
}

func TestCOSEService_HandleRequest_UnknownUUID(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: uuid.New(),
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusNotFound)
	}
}

func TestCOSEService_HandleRequest_CantGetIdentity(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: mockGetIdentityReturnsErr,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusInternalServerError)
	}
}

func TestCOSEService_HandleRequest_BadAuth(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuthBad,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set(h.AuthHeader, "12345")

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusUnauthorized)
	}
}

func TestCOSEService_HandleRequest_HashRequest_BadHash_Base64(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEServiceHandleRequest_HashRequest_BadHash_Hex(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	testHashHex := "76e114443cd386716c0f8408ce99e0017d07e68fef22ade5b39966941b35881ff"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHashHex))
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set("Content-Transfer-Encoding", HexEncoding)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_HashRequest_BadContentType(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", "wrong content type")
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_HashRequest_BadHashLen(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	tooShortHash := "x/Ef/8VDEjvybn2gvxGeiA=="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tooShortHash))
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_DataRequest_JSON(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(payloadJSON)))
	r.Header.Set("Content-Type", h.JSONType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(coseSigner.GetCBORFromJSON, coseSigner.GetSigStructBytes))(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEService_HandleRequest_DataRequest_BadJSON(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	badJSON := "absolutely not a json"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(badJSON)))
	r.Header.Set("Content-Type", h.JSONType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(coseSigner.GetCBORFromJSON, coseSigner.GetSigStructBytes))(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_DataRequest_CBOR(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	testCBOR, _ := hex.DecodeString("a164746573746568656c6c6f")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(testCBOR))
	r.Header.Set("Content-Type", h.CBORType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(coseSigner.GetCBORFromJSON, coseSigner.GetSigStructBytes))(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEService_HandleRequest_DataRequest_BadCBOR(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(nil))
	r.Header.Set("Content-Type", h.CBORType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(coseSigner.GetCBORFromJSON, coseSigner.GetSigStructBytes))(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_DataRequest_BadContentType(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: ent.Identity{
		Uid: test.Uuid,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
		CheckAuth:   mockCheckAuth,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(payloadJSON)))
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set(h.AuthHeader, string(test.Auth))

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(coseSigner.GetCBORFromJSON, coseSigner.GetSigStructBytes))(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestSendResponse(t *testing.T) {
	header := http.Header{}
	header.Set("Content-Type", h.TextType)
	header.Set("some-other-header", "i am some other header")

	resp := h.HTTPResponse{
		StatusCode: http.StatusTeapot,
		Header:     header,
		Content:    []byte("hello world"),
	}

	w := httptest.NewRecorder()

	h.SendResponse(w, resp)

	if w.Code != resp.StatusCode {
		t.Errorf("unexpected status: %d, expected: %d", w.Code, resp.StatusCode)
	}

	if w.Header().Get("Content-Type") != h.TextType {
		t.Errorf("unexpected Content-Type: %s, expected: %s", w.Header().Get("Content-Type"), h.TextType)
	}

	if w.Header().Get("some-other-header") != "i am some other header" {
		t.Errorf("unexpected Content-Type: %s, expected: \"i am some other header\"", w.Header().Get("some-other-header"))
	}

	if !bytes.Equal(w.Body.Bytes(), resp.Content) {
		t.Errorf("unexpected content: %s, expected: %s", w.Body.Bytes(), resp.Content)
	}

}

func mockGetUUIDFromURL(*http.Request) (uuid.UUID, error) {
	return test.Uuid, nil
}

func mockGetIdentityReturnsErr(uuid.UUID) (ent.Identity, error) {
	return ent.Identity{}, test.Error
}

func mockCheckAuth(context.Context, string, string) (bool, error) {
	return true, nil
}

func mockCheckAuthBad(context.Context, string, string) (bool, error) {
	return false, nil
}