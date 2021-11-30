package http_server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"

	log "github.com/sirupsen/logrus"
	prom "github.com/ubirch/ubirch-cose-client-go/main/prometheus"
)

const (
	GatewayTimeout  = 4 * time.Second  // time after which a 504 response will be sent if no timely response could be produced
	ShutdownTimeout = 5 * time.Second  // time after which the server will be shut down forcefully if graceful shutdown did not happen before
	ReadTimeout     = 1 * time.Second  // maximum duration for reading the entire request -> low since we only expect requests with small content
	WriteTimeout    = 60 * time.Second // time after which the connection will be closed if response was not written -> this should never happen
	IdleTimeout     = 60 * time.Second // time to wait for the next request when keep-alives are enabled

	UUIDKey          = "uuid"
	CBORPath         = "/cbor"
	HashEndpoint     = "/hash"
	RegisterEndpoint = "/register"
	CSREndpoint      = "/csr"

	BinType  = "application/octet-stream"
	TextType = "text/plain"
	JSONType = "application/json"
	CBORType = "application/cbor"

	AuthHeader = "X-Auth-Token"
)

var UUIDPath = fmt.Sprintf("/{%s}", UUIDKey)

type Service interface {
	HandleRequest(w http.ResponseWriter, r *http.Request)
}

type ServerEndpoint struct {
	Path string
	Service
}

func (*ServerEndpoint) HandleOptions(http.ResponseWriter, *http.Request) {
	return
}

type HTTPServer struct {
	Router   *chi.Mux
	Addr     string
	TLS      bool
	CertFile string
	KeyFile  string
}

func NewRouter() *chi.Mux {
	router := chi.NewMux()
	router.Use(prom.PromMiddleware)
	router.Use(middleware.Timeout(GatewayTimeout))
	return router
}

func (srv *HTTPServer) Serve(cancelCtx context.Context) error {
	server := &http.Server{
		Addr:         srv.Addr,
		Handler:      srv.Router,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	go func() {
		<-cancelCtx.Done()
		server.SetKeepAlivesEnabled(false) // disallow clients to create new long-running conns

		shutdownWithTimeoutCtx, _ := context.WithTimeout(shutdownCtx, ShutdownTimeout)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownWithTimeoutCtx); err != nil {
			log.Warnf("could not gracefully shut down server: %s", err)
		} else {
			log.Debug("shut down HTTP server")
		}
	}()

	log.Infof("starting HTTP server")

	var err error
	if srv.TLS {
		err = server.ListenAndServeTLS(srv.CertFile, srv.KeyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("error starting HTTP server: %v", err)
	}

	// wait for server to shut down gracefully
	<-shutdownCtx.Done()
	return nil
}
