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
	"fmt"
	p "github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"

	"golang.org/x/sync/errgroup"

	log "github.com/sirupsen/logrus"
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

func main() {
	const (
		Version    = "v1.0.0"
		Build      = "local"
		configFile = "config.json"
	)

	var configDir string
	if len(os.Args) > 1 {
		configDir = os.Args[1]
	}

	log.SetFormatter(&log.JSONFormatter{})
	log.Printf("UBIRCH COSE client (%s, build=%s)", Version, Build)

	// read configuration
	conf := Config{}
	err := conf.Load(configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	ctxManager, err := NewFileManager(conf.configDir)
	if err != nil {
		log.Fatal(err)
	}

	client := &Client{
		keyServiceURL:      conf.KeyService,
		identityServiceURL: conf.IdentityService,
		//signingServiceURL:  conf.SigningService,
	}

	protocol, err := NewProtocol(ctxManager, conf.secretBytes, client)
	if err != nil {
		log.Fatal(err)
	}

	idHandler := &IdentityHandler{
		protocol:            protocol,
		subjectCountry:      conf.CSR_Country,
		subjectOrganization: conf.CSR_Organization,
	}

	// generate and register keys for known identities
	err = idHandler.initIdentities(conf.identities)
	if err != nil {
		log.Fatal(err)
	}

	coseSigner, err := NewCoseSigner(protocol)
	if err != nil {
		log.Fatal(err)
	}

	httpServer := HTTPServer{
		router:   NewRouter(),
		addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		certFile: conf.TLS_CertFile,
		keyFile:  conf.TLS_KeyFile,
	}

	service := &COSEService{
		CoseSigner: coseSigner,
		identities: conf.identities,
	}

	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	// set up graceful shutdown handling
	go shutdown(cancel)

	RegisterPromMetrics()
	httpServer.router.Use(PromMiddleware)
	httpServer.router.Method(http.MethodGet, "/metrics", p.Handler())

	// set up endpoints for COSE signing (UUID as URL parameter)
	directUuidEndpoint := fmt.Sprintf("/{%s}/cbor", UUIDKey) // /<uuid>/cbor
	httpServer.router.Post(directUuidEndpoint, service.directUUID())

	directUuidHashEndpoint := path.Join(directUuidEndpoint, HashEndpoint) // /<uuid>/cbor/hash
	httpServer.router.Post(directUuidHashEndpoint, service.directUUID())

	// set up endpoints for COSE signing (UUID via pattern matching)
	matchUuidEndpoint := "/cbor" // /cbor
	httpServer.router.Post(matchUuidEndpoint, service.matchUUID())

	matchUuidHashEndpoint := path.Join(matchUuidEndpoint, HashEndpoint) // /cbor/hash
	httpServer.router.Post(matchUuidHashEndpoint, service.matchUUID())

	// start HTTP server
	g.Go(func() error {
		return httpServer.Serve(ctx)
	})

	// wait for all go routines of the waitgroup to return
	if err = g.Wait(); err != nil {
		log.Error(err)
	}

	log.Info("shut down")
}
