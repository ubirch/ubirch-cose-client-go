package http_server

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var (
	testUUID        = uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")
	testAuth        = "password1234!"
	testPayloadJSON = "{\"testString\": \"test\"; \"testInt\": 256}"
	testCose        = []byte{0xd2, 0x84, 0x43, 0xa1, 0x1, 0x26, 0xa1, 0x4, 0x48, 0xa3, 0x78, 0xce, 0x33, 0x3d, 0xd4, 0xf7, 0x76, 0x44, 0x74, 0x65, 0x73, 0x74, 0x58, 0x40, 0x52, 0xfd, 0xfc, 0x7, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0xf, 0x9a, 0x62, 0x1d, 0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x3, 0x7c, 0x4d, 0x7b, 0xbb, 0x4, 0x7, 0xd1, 0xe2, 0xc6, 0x49, 0x81, 0x85, 0x5a, 0xd8, 0x68, 0x1d, 0xd, 0x86, 0xd1, 0xe9, 0x1e, 0x0, 0x16, 0x79, 0x39, 0xcb, 0x66, 0x94, 0xd2, 0xc4, 0x22, 0xac, 0xd2, 0x8, 0xa0, 0x7, 0x29, 0x39, 0x48, 0x7f, 0x69, 0x99}
)

func TestCOSEServiceHandleRequest_HashRequest_Base64(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get(ErrHeader))
	assert.Equal(t, testCose, w.Body.Bytes())
}

func TestCOSEServiceHandleRequest_HashRequest_Hex(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	testHashHex := "76e114443cd386716c0f8408ce99e0017d07e68fef22ade5b39966941b35881f"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHashHex))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", TextType)
	r.Header.Set("Content-Transfer-Encoding", HexEncoding)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get(ErrHeader))
	assert.Equal(t, testCose, w.Body.Bytes())
}

func TestCOSEServiceHandleRequest_HashRequest_Bytes(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	testHashBytes, _ := hex.DecodeString("76e114443cd386716c0f8408ce99e0017d07e68fef22ade5b39966941b35881f")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(testHashBytes))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", BinType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get(ErrHeader))
	assert.Equal(t, testCose, w.Body.Bytes())
}

func TestCOSEService_HandleRequest_BadUUID(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURLBad, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, ErrCodeInvalidUUID, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_UnknownUUID(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuthNotFound,
		Sign:      mockSign,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, ErrCodeUnknownUUID, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_BadAuthCheck(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth: mockCheckAuthBad,
		Sign:      mockSign,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, ErrCodeAuthInternalServerError, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_MissingAuth(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, ErrCodeMissingAuth, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_InvalidAuth(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set(AuthHeader, "password")
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, ErrCodeInvalidAuth, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_HashRequest_BadHash_Base64(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrCodeInvalidRequestContent, w.Header().Get(ErrHeader))
}

func TestCOSEServiceHandleRequest_HashRequest_BadHash_Hex(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	testHashHex := "76e114443cd386716c0f8408ce99e0017d07e68fef22ade5b39966941b35881ff"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHashHex))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", TextType)
	r.Header.Set("Content-Transfer-Encoding", HexEncoding)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrCodeInvalidRequestContent, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_HashRequest_BadContentType(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", "wrong content type")

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrCodeInvalidRequestContent, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_HashRequest_BadHashLen(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	tooShortHash := "x/Ef/8VDEjvybn2gvxGeiA=="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tooShortHash))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrCodeInvalidRequestContent, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_DataRequest_JSON(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(testPayloadJSON)))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", JSONType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, testCOSEService.GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytes))(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_DataRequest_BadJSON(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(testPayloadJSON)))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", JSONType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, testCOSEService.GetPayloadAndHashFromDataRequest(mockGetCBORFromJSONBad, mockGetSigStructBytes))(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrCodeInvalidRequestContent, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_DataRequest_CBOR(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	testCBOR, _ := hex.DecodeString("a164746573746568656c6c6f")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(testCBOR))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", CBORType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, testCOSEService.GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytes))(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_DataRequest_BadContentType(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(testPayloadJSON)))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", TextType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, testCOSEService.GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytes))(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrCodeInvalidRequestContent, w.Header().Get(ErrHeader))
}

func TestCOSEService_HandleRequest_DataRequest_BadSigStructBytes(t *testing.T) {
	testCOSEService := &COSEService{
		CheckAuth:             mockCheckAuth,
		Sign:                  mockSign,
		LogDebugSensitiveData: func(string, ...interface{}) {},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(testPayloadJSON)))
	r.Header.Set(AuthHeader, testAuth)
	r.Header.Set("Content-Type", JSONType)

	testCOSEService.HandleRequest(mockGetUUIDFromURL, testCOSEService.GetPayloadAndHashFromDataRequest(mockGetCBORFromJSON, mockGetSigStructBytesBad))(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrCodeInvalidRequestContent, w.Header().Get(ErrHeader))
}

func mockCheckAuth(u uuid.UUID, a string) (bool, bool, error) {
	return a == testAuth, true, nil
}

func mockCheckAuthBad(uuid.UUID, string) (bool, bool, error) {
	return false, false, errors.New("mock error")
}

func mockCheckAuthNotFound(uuid.UUID, string) (bool, bool, error) {
	return false, false, nil
}

func mockSign(HTTPRequest) HTTPResponse {
	return HTTPResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {BinType}},
		Content:    testCose,
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
