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
	"flag"
	"fmt"
	"time"

	"github.com/ubirch/ubirch-cose-client-go/main/auditlogger"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"github.com/ubirch/ubirch-cose-client-go/main/profiling"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
)

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
	conf := &config.Config{}
	err := conf.Load(*configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	// set up CPU profiling if enabled by flag
	if *cpuprofile != "" {
		file := profiling.RecordCPUProfile(*cpuprofile)
		defer profiling.StopCPUProfileRecording(file)
	}

	// set up memory profiling if enabled by flag
	if *blockprofile != "" {
		file := profiling.RecordBlockProfile(*blockprofile)
		defer profiling.StopBlockProfileRecording(file)
	}

	storageManager, err := GetStorageManager(conf)
	if err != nil {
		log.Fatal(err)
	}
	defer storageManager.Close()
	readinessChecks = append(readinessChecks, storageManager.IsReady)

	err = storageManager.IsReady()
	for err != nil {
		log.Infof("db not ready yet")
		time.Sleep(200 * time.Millisecond)
		err = storageManager.IsReady()
	}
	log.Info("db ready")

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
	readinessChecks = append(readinessChecks, cryptoCtx.IsReady)

	err = cryptoCtx.SetupSession()
	if err != nil {
		// if setting up a session with the HSM fails now, continue anyway.
		// the retry handler of the PKCS#11 crypto context will try to set up
		// a session on every incoming signing request.
		log.Warnf("unable to set up session with HSM: %v", err)
	}

	protocol := NewProtocol(storageManager, conf)

	certClient := &CertificateServerClient{
		CertificateServerURL:       conf.CertificateServer,
		CertificateServerPubKeyURL: conf.CertificateServerPubKey,
		ServerTLSCertFingerprints:  conf.ServerTLSCertFingerprints,
	}

	skidHandler := NewSkidHandler(certClient.RequestCertificateList, protocol.GetUuidForPublicKey, cryptoCtx.EncodePublicKey, conf.ReloadCertsEveryMinute)

	certifyApiClient := &CertifyApiClient{
		CertifyApiURL:  conf.CertifyApiUrl,
		CertifyApiAuth: conf.CertifyApiAuth,
	}

	idHandler := &IdentityHandler{
		Protocol:            protocol,
		Crypto:              cryptoCtx,
		RegisterAuth:        certifyApiClient.RegisterSeal,
		subjectCountry:      conf.CSR_Country,
		subjectOrganization: conf.CSR_Organization,
	}

	coseSigner, err := NewCoseSigner(cryptoCtx.SignHash, skidHandler.GetSKID)
	if err != nil {
		log.Fatal(err)
	}

	// set up HTTP server
	httpServer := h.InitHTTPServer(conf,
		protocol.CheckAuth, coseSigner.Sign,
		idHandler.InitIdentity, idHandler.CreateCSR,
		coseSigner.GetCBORFromJSON, coseSigner.GetSigStructBytes,
		serverID, readinessChecks)

	// start HTTP server (blocks until SIGINT or SIGTERM is received)
	if err = httpServer.Serve(); err != nil {
		log.Error(err)
	}
}
