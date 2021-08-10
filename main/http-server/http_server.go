package http_server

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"

	log "github.com/sirupsen/logrus"
)

const (
	GatewayTimeout  = 90 * time.Second // time after which a 504 response will be sent if no timely response could be produced
	ShutdownTimeout = 25 * time.Second // time after which the server will be shut down forcefully if graceful shutdown did not happen before
	ReadTimeout     = 1 * time.Second  // maximum duration for reading the entire request -> low since we only expect requests with small content
	WriteTimeout    = 99 * time.Second // time after which the connection will be closed if response was not written -> this should never happen
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

func NewRouter(limit, backlogLimit int) *chi.Mux {
	router := chi.NewMux()
	router.Use(middleware.Timeout(GatewayTimeout))
	router.Use(middleware.ThrottleBacklog(limit, backlogLimit, time.Second))
	return router
}

func (srv *HTTPServer) SetUpCORS(allowedOrigins []string, debug bool) {
	srv.Router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "X-Auth-Token"},
		ExposedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "X-Auth-Token"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
		Debug:            debug,
	}))
}

func (srv *HTTPServer) AddServiceEndpoint(endpoint ServerEndpoint) {
	hashEndpointPath := path.Join(endpoint.Path, HashEndpoint)

	srv.Router.Post(endpoint.Path, endpoint.HandleRequest)
	srv.Router.Post(hashEndpointPath, endpoint.HandleRequest)

	srv.Router.Options(endpoint.Path, endpoint.HandleOptions)
	srv.Router.Options(hashEndpointPath, endpoint.HandleOptions)
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
