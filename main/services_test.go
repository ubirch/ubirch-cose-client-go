package main

import (
	"bytes"
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var (
	testAuth = "1234"
)

func TestCOSEServiceHandleRequest(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: Identity{
		Uid:       testUuid,
		AuthToken: testAuth,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)
	r.Header.Set(AuthHeader, testAuth)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEService_HandleRequest_BadUUID(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: Identity{
		Uid:       testUuid,
		AuthToken: testAuth,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)
	r.Header.Set(AuthHeader, testAuth)

	testCOSEService.handleRequest(getUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusNotFound)
	}
}

func TestCOSEService_HandleRequest_UnknownUUID(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: Identity{
		Uid:       uuid.New(),
		AuthToken: testAuth,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)
	r.Header.Set(AuthHeader, testAuth)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

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
	r.Header.Set("Content-Type", TextType)
	r.Header.Set(AuthHeader, testAuth)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusInternalServerError)
	}
}

func TestCOSEService_HandleRequest_BadAuth(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: Identity{
		Uid:       testUuid,
		AuthToken: testAuth,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)
	r.Header.Set(AuthHeader, "12345")

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEService_HandleRequest_BadHash(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: Identity{
		Uid:       testUuid,
		AuthToken: testAuth,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g"

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", TextType)
	r.Header.Set(AuthHeader, testAuth)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_BadContentType(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: Identity{
		Uid:       testUuid,
		AuthToken: testAuth,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
	}

	testHash := "9HKjChmwbHoHpMuX1OXgUgf6bPLNrQT/mCXw0JUk37g="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testHash))
	r.Header.Set("Content-Type", "wrong content type")
	r.Header.Set(AuthHeader, testAuth)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_BadHashLen(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: Identity{
		Uid:       testUuid,
		AuthToken: testAuth,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
	}

	tooShortHash := "x/Ef/8VDEjvybn2gvxGeiA=="

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tooShortHash))
	r.Header.Set("Content-Type", TextType)
	r.Header.Set(AuthHeader, testAuth)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetHashFromHashRequest())(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func TestCOSEService_HandleRequest_DataRequest(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: Identity{
		Uid:       testUuid,
		AuthToken: testAuth,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(payloadJSON)))
	r.Header.Set("Content-Type", JSONType)
	r.Header.Set(AuthHeader, testAuth)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(coseSigner.GetCBORFromJSON, coseSigner.GetSigStructBytes))(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusOK)
	}
}

func TestCOSEService_HandleRequest_DataRequest_BadContentType(t *testing.T) {
	coseSigner, err := NewCoseSigner(mockSign, mockGetSKID)
	if err != nil {
		t.Fatal(err)
	}

	ctxMngr := mockCtxMngr{id: Identity{
		Uid:       testUuid,
		AuthToken: testAuth,
	}}

	testCOSEService := &COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: ctxMngr.GetIdentity,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(payloadJSON)))
	r.Header.Set("Content-Type", TextType)
	r.Header.Set(AuthHeader, testAuth)

	testCOSEService.handleRequest(mockGetUUIDFromURL, GetPayloadAndHashFromDataRequest(coseSigner.GetCBORFromJSON, coseSigner.GetSigStructBytes))(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response status: %d, expected: %d", w.Code, http.StatusBadRequest)
	}
}

func mockGetUUIDFromURL(*http.Request) (uuid.UUID, error) {
	return testUuid, nil
}

func mockGetIdentityReturnsErr(uid uuid.UUID) (*Identity, error) {
	return nil, fmt.Errorf("test error")
}
