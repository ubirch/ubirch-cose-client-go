// Copyright (c) 2021 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/ubirch/ubirch-cose-client-go/main/auditlogger"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	prom "github.com/ubirch/ubirch-cose-client-go/main/prometheus"
)

// handle graceful shutdown
func shutdown(cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Infof("shutting down after receiving: %v", sig)

	// cancel the go routines contexts
	cancel()
}

var (
	// Version will be replaced with the tagged version during build time
	Version = "local build"
	// Revision will be replaced with the commit hash during build time
	Revision = "unknown"
	// declare flags
	configDir = flag.String("configdirectory", "", "configuration `directory` to use")
)

func main() {
	const (
		serviceName = "cose-client"
		configFile  = "config.json"
	)

	var (
		serverID        = fmt.Sprintf("%s/%s", serviceName, Version)
		readinessChecks []func() error
	)

	// parse commandline flags
	flag.Parse()

	log.SetFormatter(&log.JSONFormatter{})
	log.Printf("UBIRCH COSE client (version=%s, revision=%s)", Version, Revision)
	auditlogger.SetServiceName(serviceName)

	// read configuration
	conf := &Config{}
	err := conf.Load(*configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	storageManager, err := GetStorageManager(conf)
	if err != nil {
		log.Fatal(err)
	}
	defer storageManager.Close()
	readinessChecks = append(readinessChecks, storageManager.IsReady)

	protocol, err := NewProtocol(storageManager, conf.secretBytes)
	if err != nil {
		log.Fatal(err)
	}

	certClient := &CertificateServerClient{
		CertificateServerURL:       conf.CertificateServer,
		CertificateServerPubKeyURL: conf.CertificateServerPubKey,
		ServerTLSCertFingerprints:  conf.serverTLSCertFingerprints,
	}

	skidHandler := NewSkidHandler(certClient.RequestCertificateList, protocol.GetUuidForPublicKey, protocol.Crypto.EncodePublicKey, conf.ReloadCertsEveryMinute)

	certifyApiClient := &CertifyApiClient{
		CertifyApiURL:  conf.CertifyApiUrl,
		CertifyApiAuth: conf.CertifyApiAuth,
	}

	idHandler := &IdentityHandler{
		Protocol:            protocol,
		RegisterAuth:        certifyApiClient.RegisterSeal,
		subjectCountry:      conf.CSR_Country,
		subjectOrganization: conf.CSR_Organization,
	}

	coseSigner, err := NewCoseSigner(protocol.Crypto.SignHash, skidHandler.GetSKID)
	if err != nil {
		log.Fatal(err)
	}

	service := &COSEService{
		GetIdentity: protocol.GetIdentity,
		Sign:        coseSigner.Sign,
	}

	// set up HTTP server
	httpServer := h.HTTPServer{
		Router:   h.NewRouter(),
		Addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		CertFile: conf.TLS_CertFile,
		KeyFile:  conf.TLS_KeyFile,
	}

	// set up metrics
	httpServer.Router.Method(http.MethodGet, "/metrics", prom.Handler())

	// set up endpoint for identity registration
	httpServer.Router.Put(h.RegisterEndpoint, h.Register(conf.RegisterAuth, idHandler.InitIdentity))

	// set up endpoint for CSRs
	fetchCSREndpoint := path.Join(h.UUIDPath, h.CSREndpoint) // /<uuid>/csr
	httpServer.Router.Get(fetchCSREndpoint, h.FetchCSR(conf.RegisterAuth, idHandler.CreateCSR))

	// set up endpoints for COSE signing (UUID as URL parameter)
	directUuidEndpoint := path.Join(h.UUIDPath, h.CBORPath) // /<uuid>/cbor
	httpServer.Router.Post(directUuidEndpoint, service.handleRequest(getUUIDFromURL, GetPayloadAndHashFromDataRequest(coseSigner.GetCBORFromJSON, coseSigner.GetSigStructBytes)))

	directUuidHashEndpoint := path.Join(directUuidEndpoint, h.HashEndpoint) // /<uuid>/cbor/hash
	httpServer.Router.Post(directUuidHashEndpoint, service.handleRequest(getUUIDFromURL, GetHashFromHashRequest()))

	// set up endpoints for liveness and readiness checks
	httpServer.Router.Get("/healthz", h.Healthz(serverID))
	httpServer.Router.Get("/readyz", h.Readyz(serverID, readinessChecks))

	// set up graceful shutdown handling
	ctx, cancel := context.WithCancel(context.Background())
	go shutdown(cancel)

	// start HTTP server (blocks)
	if err = httpServer.Serve(ctx); err != nil {
		log.Error(err)
	}

	log.Debug("shut down")
}
