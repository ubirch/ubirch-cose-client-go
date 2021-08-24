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
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-cose-client-go/main/auditlogger"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

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

	//write the blocking profile at the moment of shutdown (if enabled by flag)
	if *blockprofile != "" {
		log.Infof("writing blocking profile data to file: %s", *blockprofile)
		f, err := os.Create(*blockprofile)
		if err != nil {
			log.Fatal("could not create blocking profile file: ", err)
		}
		if err := pprof.Lookup("block").WriteTo(f, 0); err != nil {
			log.Fatal("could not write blocking profile: ", err)
		}
		if err := f.Close(); err != nil {
			log.Fatal("error when closing blocking profile file: ", err)
		}
	}

	// cancel the go routines contexts
	cancel()
}

var (
	// Version will be replaced with the tagged version during build time
	Version = "local build"
	// Revision will be replaced with the commit hash during build time
	Revision = "unknown"
	// declare flags
	cpuprofile   = flag.String("cpuprofile", "", "write cpu profile to `file`")
	blockprofile = flag.String("blockprofile", "", "write blocking profile (at point of shutdown) to `file`")
	configDir    = flag.String("configdirectory", "", "configuration `directory` to use")
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

	// set up CPU profiling if enabled by flag
	if *cpuprofile != "" {
		log.Infof("enabling CPU profiling to file: %s", *cpuprofile)
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatalf("could not create CPU profile file: %s", err)
		}
		defer func(myF *os.File) {
			err := myF.Close()
			if err != nil {
				log.Fatalf("error when closing CPU profile file: %s", err)
			}
		}(f)
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatalf("could not start CPU profile: %s", err)
		}
		defer pprof.StopCPUProfile()
	}

	// print info if memory profiling is enabled
	if *blockprofile != "" {
		log.Warn("blocking profiling enabled, this will affect performance, file: ", *blockprofile)
		runtime.SetBlockProfileRate(1)
	}

	// initialize COSE service
	cryptoCtx, err := ubirch.NewECDSAPKCS11CryptoContext(conf.PKCS11Module, conf.PKCS11ModulePin,
		conf.PKCS11ModuleSlotNr, true, 1, 50*time.Millisecond)
	if err != nil {
		log.Fatalf("failed to initialize PKCS#11 crypto context (HSM): %v", err)
	}
	defer func() {
		err := cryptoCtx.Close()
		if err != nil {
			log.Error(err)
		}
	}()

	err = cryptoCtx.SetupSession()
	if err != nil {
		// if setting up a session with the HSM fails now, continue anyway.
		// the retry handler of the PKCS#11 crypto context will try to set up
		// a session on every incoming signing request.
		log.Warnf("unable to set up session with HSM: %v", err)
	}
	defer func() {
		err := cryptoCtx.TeardownSession()
		if err != nil {
			log.Error(err)
		}
	}()
	readinessChecks = append(readinessChecks, cryptoCtx.IsReady)

	storageManager, err := GetStorageManager(conf)
	if err != nil {
		log.Fatal(err)
	}
	defer storageManager.Close()
	readinessChecks = append(readinessChecks, storageManager.IsReady)

	protocol := NewProtocol(storageManager, conf.KdMaxTotalMemMiB, conf.kdParams)

	//certClient := &CertificateServerClient{
	//	CertificateServerURL:       conf.CertificateServer,
	//	CertificateServerPubKeyURL: conf.CertificateServerPubKey,
	//	ServerTLSCertFingerprints:  conf.serverTLSCertFingerprints,
	//}
	//
	//skidHandler := NewSkidHandler(certClient.RequestCertificateList, protocol.GetUuidForPublicKey, cryptoCtx.EncodePublicKey, conf.ReloadCertsEveryMinute)

	idHandler := &IdentityHandler{
		Protocol:            protocol,
		Crypto:              cryptoCtx,
		subjectCountry:      conf.CSR_Country,
		subjectOrganization: conf.CSR_Organization,
	}

	//coseSigner, err := NewCoseSigner(cryptoCtx.SignHash, skidHandler.GetSKID)
	coseSigner, err := NewCoseSigner(cryptoCtx.SignHash, getSKID) // FIXME
	if err != nil {
		log.Fatal(err)
	}
	log.Warnf("USING MOCK SKID") // FIXME

	service := &COSEService{
		GetIdentity: protocol.GetIdentity,
		CheckAuth:   protocol.pwHasher.CheckPassword,
		Sign:        coseSigner.Sign,
	}

	// set up HTTP server
	httpServer := h.HTTPServer{
		Router:   h.NewRouter(conf.RequestLimit, conf.RequestBacklogLimit),
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

func getSKID(uuid.UUID) ([]byte, error) {
	return make([]byte, 8), nil
}
