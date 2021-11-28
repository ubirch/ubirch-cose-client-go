package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
)

func TestCOSEServiceHandleRequest_HashRequest_Base64(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuth,
		Sign:      mockSign,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", h.TextType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set("Content-Transfer-Encoding", HexEncoding)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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
	r.Header.Set("Content-Type", h.BinType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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
	r.Header.Set("Content-Type", h.TextType)

	testCOSEService.handleRequest(mockGetUUIDFromURLBad, GetHashFromHashRequest())(w, r)

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
	r.Header.Set("Content-Type", h.TextType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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
	r.Header.Set("Content-Type", h.TextType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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
	r.Header.Set("Content-Type", h.TextType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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
	r.Header.Set("Content-Type", h.TextType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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
	r.Header.Set("Content-Type", h.TextType)
	r.Header.Set("Content-Transfer-Encoding", HexEncoding)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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
	r.Header.Set("Content-Type", h.TextType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(payloadJSON)))
	r.Header.Set("Content-Type", h.JSONType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytes))(w, r)

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
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(payloadJSON)))
	r.Header.Set("Content-Type", h.JSONType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(mockGetCBORFromJSONBad, mockGetSigStructBytes))(w, r)

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
	r.Header.Set("Content-Type", h.CBORType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytes))(w, r)

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
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(payloadJSON)))
	r.Header.Set("Content-Type", h.TextType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytes))(w, r)

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
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(payloadJSON)))
	r.Header.Set("Content-Type", h.JSONType)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytesBad))(w, r)

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

func mockCheckAuth(context.Context, uuid.UUID, string) (bool, bool, error) {
	return true, true, nil
}

func mockCheckAuthBad(context.Context, uuid.UUID, string) (bool, bool, error) {
	return false, false, test.Error
}

func mockCheckAuthNotFound(context.Context, uuid.UUID, string) (bool, bool, error) {
	return false, false, nil
}

func mockCheckAuthNotOk(context.Context, uuid.UUID, string) (bool, bool, error) {
	return false, true, nil
}

func mockSign(HTTPRequest) h.HTTPResponse {
	return h.HTTPResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {h.BinType}},
		Content:    []byte("mock"),
	}
}

func mockGetUUIDFromURL(*http.Request) (uuid.UUID, error) {
	return test.Uuid, nil
}

func mockGetUUIDFromURLBad(*http.Request) (uuid.UUID, error) {
	return uuid.Nil, test.Error
}

func mockGetCBORFromJSON([]byte) ([]byte, error) {
	return []byte("mock CBOR"), nil
}

func mockGetCBORFromJSONBad([]byte) ([]byte, error) {
	return nil, test.Error
}

func mockGetSigStructBytes([]byte) ([]byte, error) {
	return []byte("mock signature struct bytes"), nil
}

func mockGetSigStructBytesBad([]byte) ([]byte, error) {
	return nil, test.Error
}
