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

	"github.com/ubirch/ubirch-cose-client-go/main/auditlogger"
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	"github.com/ubirch/ubirch-cose-client-go/main/profiling"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-cose-client-go/main/http-server"
)

var (
	// Version will be replaced with the tagged version during build time
	Version = "local build"
	// Revision will be replaced with the commit hash during build time
	Revision = "unknown"
)

func main() {
	const (
		serviceName = "cose-client"
		configFile  = "config.json"
	)

	var (
		serverID        = fmt.Sprintf("%s/%s", serviceName, Version)
		readinessChecks []func() error

		// declare command-line flags
		cpuprofile   = flag.String("cpuprofile", "", "write cpu profile to `file`")
		blockprofile = flag.String("blockprofile", "", "write blocking profile (at point of shutdown) to `file`")
		configDir    = flag.String("configdirectory", "", "configuration `directory` to use")
	)

	// parse command-line flags
	flag.Parse()

	log.SetFormatter(&log.JSONFormatter{
		FieldMap: log.FieldMap{
			log.FieldKeyMsg: "message",
		},
	})
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

	// initialize COSE service
	storageManager, err := GetStorageManager(conf)
	if err != nil {
		log.Fatal(err)
	}
	defer storageManager.Close()
	readinessChecks = append(readinessChecks, storageManager.IsReady)

	protocol, err := NewProtocol(storageManager, conf)
	if err != nil {
		log.Fatal(err)
	}

	certClient := &CertificateServerClient{
		CertificateServerURL:       conf.CertificateServer,
		CertificateServerPubKeyURL: conf.CertificateServerPubKey,
		ServerTLSCertFingerprints:  conf.ServerTLSCertFingerprints,
	}

	skidHandler := NewSkidHandler(certClient.RequestCertificateList, protocol.GetUuidForPublicKey, protocol.Crypto.EncodePublicKey, conf.ReloadCertsEveryMinute, conf.IgnoreUnknownCerts)

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
