package http_server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

var (
	testUUID        = uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")
	testAuth        = "password1234!"
	testPayloadJSON = "{\"testString\": \"test\"; \"testInt\": 256}"
)

func TestCOSEServiceHandleRequest_HashRequest_Base64(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEServiceHandleRequest_HashRequest_Hex(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	testHashHex := "76e114443cd386716c0f8408ce99e0017d07e68fef22ade5b39966941b35881f"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHashHex))
	r.Header.Set("Content-Type", TextType)
	r.Header.Set("Content-Transfer-Encoding", HexEncoding)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEServiceHandleRequest_HashRequest_Bytes(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	testHashBytes, _ := hex.DecodeString("76e114443cd386716c0f8408ce99e0017d07e68fef22ade5b39966941b35881f")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(testHashBytes))
	r.Header.Set("Content-Type", BinType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEService_HandleRequest_BadUUID(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURLBad, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusNotFound)
	}
}

func TestCOSEService_HandleRequest_UnknownUUID(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuthNotFound,
		Sign:      mockSign,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusNotFound)
	}
}

func TestCOSEService_HandleRequest_BadAuthCheck(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuthBad,
		Sign:      mockSign,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusInternalServerError)
	}
}

func TestCOSEService_HandleRequest_BadAuth(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuthNotOk,
		Sign:      mockSign,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusUnauthorized)
	}
}

func TestCOSEService_HandleRequest_HashRequest_BadHash_Base64(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEServiceHandleRequest_HashRequest_BadHash_Hex(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	testHashHex := "76e114443cd386716c0f8408ce99e0017d07e68fef22ade5b39966941b35881ff"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHashHex))
	r.Header.Set("Content-Type", TextType)
	r.Header.Set("Content-Transfer-Encoding", HexEncoding)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_HashRequest_BadContentType(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", "wrong content type")

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_HashRequest_BadHashLen(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	tooShortHash := "x/Ef/8VDEjvybn2gvxGeiA=="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tooShortHash))
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_DataRequest_JSON(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(testPayloadJSON)))
	r.Header.Set("Content-Type", JSONType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytes))(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEService_HandleRequest_DataRequest_BadJSON(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(testPayloadJSON)))
	r.Header.Set("Content-Type", JSONType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(mockGetCBORFromJSONBad, mockGetSigStructBytes))(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_DataRequest_CBOR(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	testCBOR, _ := hex.DecodeString("a164746573746568656c6c6f")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(testCBOR))
	r.Header.Set("Content-Type", CBORType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytes))(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEService_HandleRequest_DataRequest_BadContentType(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(testPayloadJSON)))
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytes))(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_DataRequest_BadSigStructBytes(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(testPayloadJSON)))
	r.Header.Set("Content-Type", JSONType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytesBad))(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func mockCheckAuth(context.Context, uuid.UUID, string) (bool, bool, error) {
	return true, true, nil
}

func mockCheckAuthBad(context.Context, uuid.UUID, string) (bool, bool, error) {
	return false, false, errors.New("mock error")
}

func mockCheckAuthNotFound(context.Context, uuid.UUID, string) (bool, bool, error) {
	return false, false, nil
}

func mockCheckAuthNotOk(context.Context, uuid.UUID, string) (bool, bool, error) {
	return false, true, nil
}

func mockSign(HTTPRequest) HTTPResponse {
	return HTTPResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {BinType}},
		Content:    []byte("mock"),
	}
}

func mockGetUUIDFromURL(*http.Request) (uuid.UUID, error) {
	return testUUID, nil
}

func mockGetUUIDFromURLBad(*http.Request) (uuid.UUID, error) {
	return uuid.Nil, errors.New("mock error")
}

func mockGetCBORFromJSON([]byte) ([]byte, error) {
	return []byte("mock CBOR"), nil
}

func mockGetCBORFromJSONBad([]byte) ([]byte, error) {
	return nil, errors.New("mock error")
}

func mockGetSigStructBytes([]byte) ([]byte, error) {
	return []byte("mock signature struct bytes"), nil
}

func mockGetSigStructBytesBad([]byte) ([]byte, error) {
	return nil, errors.New("mock error")
}
