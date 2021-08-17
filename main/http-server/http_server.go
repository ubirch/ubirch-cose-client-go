package http_server

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server/helper"
	prom "github.com/ubirch/ubirch-cose-client-go/main/prometheus"
	repo "github.com/ubirch/ubirch-cose-client-go/main/repository"
	"net/http"
	"path"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"

	log "github.com/sirupsen/logrus"
)



var UUIDPath = fmt.Sprintf("/{%s}", h.UUIDKey)

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
	router.Use(middleware.Timeout(h.GatewayTimeout))
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
	hashEndpointPath := path.Join(endpoint.Path, h.HashEndpoint)

	srv.Router.Post(endpoint.Path, endpoint.HandleRequest)
	srv.Router.Post(hashEndpointPath, endpoint.HandleRequest)

	srv.Router.Options(endpoint.Path, endpoint.HandleOptions)
	srv.Router.Options(hashEndpointPath, endpoint.HandleOptions)
}

func (srv *HTTPServer) Serve(cancelCtx context.Context) error {
	server := &http.Server{
		Addr:         srv.Addr,
		Handler:      srv.Router,
		ReadTimeout:  h.ReadTimeout,
		WriteTimeout: h.WriteTimeout,
		IdleTimeout:  h.IdleTimeout,
	}
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	go shutdownServer(cancelCtx, server, shutdownCtx, shutdownCancel)

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

func shutdownServer(cancelCtx context.Context, server *http.Server, shutdownCtx context.Context, shutdownCancel context.CancelFunc) {
	<-cancelCtx.Done()
	server.SetKeepAlivesEnabled(false) // disallow clients to create new long-running conns

	shutdownWithTimeoutCtx, _ := context.WithTimeout(shutdownCtx, h.ShutdownTimeout)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownWithTimeoutCtx); err != nil {
		log.Warnf("could not gracefully shut down server: %s", err)
	} else {
		log.Debug("shut down HTTP server")
	}
}

func NewServer(conf *config.Config, serverID string, protocol *repo.Protocol) HTTPServer {
	// set up HTTP server
	httpServer := HTTPServer{
		Router:   NewRouter(conf.RequestLimit, conf.RequestBacklogLimit),
		Addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		CertFile: conf.TLS_CertFile,
		KeyFile:  conf.TLS_KeyFile,
	}

	// set up metrics
	prom.InitPromMetrics(httpServer.Router)

	// set up endpoint for liveliness checks
	httpServer.Router.Get("/healtz", h.Health(serverID))

	idHandler := &repo.IdentityHandler{
		Protocol:            protocol,
		SubjectCountry:      conf.CSR_Country,
		SubjectOrganization: conf.CSR_Organization,
	}

	coseSigner, err := repo.NewCoseSigner(protocol.Crypto.SignHash, getSKID) // FIXME
	if err != nil {
		log.Fatal(err)
	}

	service := &repo.COSEService{
		CoseSigner:  coseSigner,
		GetIdentity: protocol.GetIdentity,
		CheckAuth:   protocol.PwHasher.CheckPassword,
	}

	// set up endpoint for identity registration
	httpServer.Router.Put(h.RegisterEndpoint, Register(conf.RegisterAuth, idHandler.InitIdentity))

	// set up endpoint for CSRs
	fetchCSREndpoint := path.Join(UUIDPath, h.CSREndpoint) // /<uuid>/csr
	httpServer.Router.Get(fetchCSREndpoint, FetchCSR(conf.RegisterAuth, idHandler.CreateCSR))

	// set up endpoints for COSE signing (UUID as URL parameter)
	directUuidEndpoint := path.Join(UUIDPath, h.CBORPath) // /<uuid>/cbor
	httpServer.Router.Post(directUuidEndpoint, service.HandleRequest(repo.GetUUIDFromURL, repo.GetPayloadAndHashFromDataRequest(coseSigner.GetCBORFromJSON, coseSigner.GetSigStructBytes)))

	directUuidHashEndpoint := path.Join(directUuidEndpoint, h.HashEndpoint) // /<uuid>/cbor/hash
	httpServer.Router.Post(directUuidHashEndpoint, service.HandleRequest(repo.GetUUIDFromURL, repo.GetHashFromHashRequest()))

	// set up endpoint for readiness checks
	httpServer.Router.Get("/readiness", h.Health(serverID))
	log.Info("ready")

	log.Warnf("USING MOCK SKID") // FIXME
	return httpServer
}

func getSKID(uuid.UUID) ([]byte, error) {
	log.Warnf("USING MOCK SKID")
	return make([]byte, 8), nil
}
