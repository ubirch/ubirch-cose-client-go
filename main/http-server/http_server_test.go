package http_server
//
//import (
//	"github.com/golang/mock/gomock"
//	"github.com/google/uuid"
//	"github.com/stretchr/testify/require"
//	"github.com/ubirch/ubirch-cose-client-go/main/config"
//	h "github.com/ubirch/ubirch-cose-client-go/main/http-server/helper"
//	pw "github.com/ubirch/ubirch-cose-client-go/main/password-hashing"
//	repo "github.com/ubirch/ubirch-cose-client-go/main/repository"
//	test "github.com/ubirch/ubirch-cose-client-go/main/tests"
//	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
//	"net/http"
//	"net/http/httptest"
//	"path"
//	"testing"
//)
//
//func TestNewServer(t *testing.T) {
//	testUuid := uuid.New()
//	testCases := []struct {
//		name      string
//		callerUrl string
//		tcChecks  func(t *testing.T, recorder *httptest.ResponseRecorder)
//	}{
//		{
//			name:      "Register Route found",
//			callerUrl: path.Join("/", testUuid.String(), h.CSREndpoint),
//			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
//				require.NotEqual(t, http.StatusNotFound, recorder.Code)
//			},
//		},
//	}
//	for _, c := range testCases {
//		t.Run(c.name, func(t *testing.T) {
//
//			ctrl := gomock.NewController(t)
//			defer ctrl.Finish()
//
//			mockProtocols := test.NewMockProtocols(ctrl)
//
//			conf := &config.Config{}
//			conf.Load("./../config", "example_config.json")
//			recorder := httptest.NewRecorder()
//			server := NewServer(conf, "", mockProtocols)
//
//			req := httptest.NewRequest(http.MethodGet, c.callerUrl, nil)
//
//			server.Router.ServeHTTP(recorder, req)
//		})
//	}
//}