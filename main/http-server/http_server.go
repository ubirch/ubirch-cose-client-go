package http_server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/ubirch/ubirch-cose-client-go/main/config"

	log "github.com/sirupsen/logrus"
	prom "github.com/ubirch/ubirch-cose-client-go/main/prometheus"
)

const (
	GatewayTimeout  = 4 * time.Second  // time after which a 504 response will be sent if no timely response could be produced
	ShutdownTimeout = 5 * time.Second  // time after which the server will be shut down forcefully if graceful shutdown did not happen before
	ReadTimeout     = 1 * time.Second  // maximum duration for reading the entire request -> low since we only expect requests with small content
	WriteTimeout    = 60 * time.Second // time after which the connection will be closed if response was not written -> this should never happen
	IdleTimeout     = 60 * time.Second // time to wait for the next request when keep-alives are enabled

	UUIDKey                = "uuid"
	SealPath               = "/seal"
	CBORPath               = "/cbor"
	HashEndpoint           = "/hash"
	RegisterEndpoint       = "/register"
	CSREndpoint            = "/csr"
	MetricsEndpoint        = "/metrics"
	LivenessCheckEndpoint  = "/healthz"
	ReadinessCheckEndpoint = "/readyz"

	BinType  = "application/octet-stream"
	TextType = "text/plain"
	JSONType = "application/json"
	CBORType = "application/cbor"

	AuthHeader = "X-Auth-Token"
	ErrHeader  = "X-Err"

	// response error codes
	ErrCodeInvalidUUID                = "CS404-0000"
	ErrCodeMissingAuth                = "CS401-0100"
	ErrCodeUnknownUUID                = "CS401-0200"
	ErrCodeInvalidAuth                = "CS401-0300"
	ErrCodeInvalidRequestContent      = "CS400-0400"
	ErrCodeAuthInternalServerError    = "CS500-0500"
	ErrCodeGenericInternalServerError = "CS500-1500"
	ErrCodeAlreadyInitialized         = "CS409-1900"
)

var UUIDPath = fmt.Sprintf("/{%s}", UUIDKey)

type Service interface {
	HandleRequest(w http.ResponseWriter, r *http.Request)
}

type ServerEndpoint struct {
	Path string
	Service
}

func (*ServerEndpoint) HandleOptions(http.ResponseWriter, *http.Request) {}

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

func InitHTTPServer(conf *config.Config,
	checkAuth CheckAuth, sign Sign,
	initialize InitializeIdentity, getCSR GetCSR,
	getCBORFromJSON GetCBORFromJSON, getSigStructBytes GetSigStructBytes,
	serverID string, readinessChecks []func() error) *HTTPServer {

	httpServer := &HTTPServer{
		Router:   NewRouter(),
		Addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		CertFile: conf.TLS_CertFile,
		KeyFile:  conf.TLS_KeyFile,
	}

	signingService := &COSEService{
		CheckAuth: checkAuth,
		Sign:      sign,
		LogDebugSensitiveData: func(format string, args ...interface{}) {
			if conf.IsDevelopment {
				log.Debugf(format, args...)
			}
		},
	}

	httpServer.Router.Route(SealPath, func(r chi.Router) {
		r.Use(middleware.ThrottleBacklog(conf.RequestLimit, conf.RequestBacklogLimit, 100*time.Millisecond))

		//// todo >>>> delete after grace period from here >>>>
		//// set up routes under /<uuid> path for backwards compatibility
		httpServer.Router.Route(UUIDPath, func(r chi.Router) {
			r.Use(middleware.ThrottleBacklog(conf.RequestLimit, conf.RequestBacklogLimit, 100*time.Millisecond))
			// set up endpoint for CSRs: /<uuid>/csr
			r.Get(CSREndpoint, FetchCSR(conf.RegisterAuth, GetUUIDFromRequest, getCSR))
			// set up endpoint for COSE CBOR signing: /<uuid>/cbor
			r.Post(CBORPath, signingService.HandleRequest(GetUUIDFromRequest, signingService.GetPayloadAndHashFromDataRequest(getCBORFromJSON, getSigStructBytes)))
			// set up endpoint for COSE CBOR hash signing: /<uuid>/cbor/hash
			r.Post(path.Join(CBORPath, HashEndpoint), signingService.HandleRequest(GetUUIDFromRequest, GetHashFromHashRequest()))
		})

		// set up endpoint for identity registration on /register endpoint for backwards compatibility
		httpServer.Router.Put(RegisterEndpoint, Register(conf.RegisterAuth, initialize))

		//// todo <<<< delete after grace period until here <<<<
		// set up endpoint for identity registration /seal/register
		r.Put(RegisterEndpoint, Register(conf.RegisterAuth, initialize))

		r.Route(UUIDPath, func(r chi.Router) {
			// set up endpoint for CSRs: /seal/<uuid>/csr
			r.Get(CSREndpoint, FetchCSR(conf.RegisterAuth, GetUUIDFromRequest, getCSR))
			// set up endpoint for COSE CBOR signing: /seal/<uuid>/cbor
			r.Post(CBORPath, signingService.HandleRequest(GetUUIDFromRequest, signingService.GetPayloadAndHashFromDataRequest(getCBORFromJSON, getSigStructBytes)))
			// set up endpoint for COSE CBOR hash signing: /seal/<uuid>/cbor/hash
			r.Post(path.Join(CBORPath, HashEndpoint), signingService.HandleRequest(GetUUIDFromRequest, GetHashFromHashRequest()))
		})
	})

	// set up endpoint for metrics
	httpServer.Router.Method(http.MethodGet, MetricsEndpoint, prom.Handler())

	// set up endpoints for liveness and readiness checks
	httpServer.Router.Get(LivenessCheckEndpoint, Health(serverID))
	httpServer.Router.Get("/healtz", Health(serverID)) // this is here for backwards compatibility and will be removed after a grace period

	httpServer.Router.Get(ReadinessCheckEndpoint, Ready(serverID, readinessChecks))

	return httpServer
}

func (srv *HTTPServer) Serve() error {
	cancelCtx, cancel := context.WithCancel(context.Background())
	go shutdown(cancel)

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

		shutdownWithTimeoutCtx, shutdownWithTimeoutCancel := context.WithTimeout(shutdownCtx, ShutdownTimeout)
		defer shutdownWithTimeoutCancel()
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

// shutdown handles graceful shutdown of the server when SIGINT or SIGTERM is received
func shutdown(cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Infof("shutting down after receiving: %v", sig)

	// cancel the contexts
	cancel()
}
