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
	"github.com/ubirch/ubirch-cose-client-go/main/config"
	http_server "github.com/ubirch/ubirch-cose-client-go/main/http-server"
	"github.com/ubirch/ubirch-cose-client-go/main/repository"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-cose-client-go/main/auditlogger"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
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
		serverID = fmt.Sprintf("%s/%s", serviceName, Version)
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

	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	ctx, cancel := context.WithCancel(context.Background())

	// set up graceful shutdown handling
	go shutdown(cancel)

	// initialize COSE service
	cryptoCtx, err := ubirch.NewECDSAPKCS11CryptoContext(
		conf.PKCS11Module,
		conf.PKCS11ModulePin,
		conf.PKCS11ModuleSlotNr,
		true,
		1,
		50*time.Millisecond)
	if err != nil {
		log.Fatalf("failed to initialize ECDSA PKCS#11 crypto context (HSM): %v", err)
	}
	defer func() {
		err := cryptoCtx.Close()
		if err != nil {
			log.Error(err)
		}
	}()

	ctxManager, err := repository.GetCtxManager(conf)
	if err != nil {
		log.Fatal(err)
	}
	defer ctxManager.Close()

	protocol := repository.NewProtocol(cryptoCtx, ctxManager, conf.KdMaxTotalMemMiB, conf.KdParams)
	defer protocol.Close()

	//client := &Client{
	//	CertificateServerURL:       conf.CertificateServer,
	//	CertificateServerPubKeyURL: conf.CertificateServerPubKey,
	//	ServerTLSCertFingerprints:  conf.serverTLSCertFingerprints,
	//}
	//
	//skidHandler := NewSkidHandler(client.RequestCertificateList, protocol.GetUuidForPublicKey, cryptoCtx.EncodePublicKey, conf.ReloadCertsEveryMinute)

	httpServer := http_server.NewServer(conf, serverID, protocol)

	// start HTTP server
	httpServer.Serve(ctx)

	log.Debug("shut down")
}




