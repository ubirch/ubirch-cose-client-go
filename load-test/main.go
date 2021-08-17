package main

import (
	"flag"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	numberOfTestIDs        = 100
	numberOfRequestsPerID  = 10
	requestsPerSecondPerID = 1
)

var (
	defaultConfigFile = "config.json"
	configFile        = flag.String("config", "", "file name of the configuration file. if omitted, configuration is read from \"config.json\".")
	outFile           = flag.String("out", "", "file name for output. if omitted, output is written to std out.")
)

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})

	flag.Parse()

	if len(*outFile) != 0 {
		fileHandle, err := os.OpenFile(filepath.Clean(*outFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			_, _ = fileHandle.WriteString("\n========================================================================================================================\n\n")
			if fileCloseErr := fileHandle.Close(); fileCloseErr != nil {
				log.Error(fileCloseErr)
			}
		}()
		log.SetOutput(fileHandle)
	}

	if len(*configFile) == 0 {
		*configFile = defaultConfigFile
	}

	c := Config{}
	err := c.Load(*configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	identities := c.getTestIdentities()
	sender := NewSender()

	for id, auth := range identities {
		err := sender.register(c.Url, id, auth, c.RegisterAuth)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Infof("%d identities, %d requests each => sending [ %d ] requests", len(identities), numberOfRequestsPerID, len(identities)*numberOfRequestsPerID)
	log.Infof("%3d requests per second per identity", requestsPerSecondPerID)
	log.Infof("%3d requests per second overall", len(identities)*requestsPerSecondPerID)

	wg := &sync.WaitGroup{}
	start := time.Now()

	for uid, auth := range identities {
		wg.Add(1)
		go sender.sendRequests(c.Url, uid, auth, wg)
	}

	wg.Wait()
	end := time.Now()
	duration := end.Sub(start)
	log.Infof("[ %4d ] requests done after [ %7.3f ] seconds ", len(identities)*numberOfRequestsPerID, duration.Seconds())

	for status, count := range sender.statusCounter {
		log.Infof("[ %4d ] x %s", count, status)
	}

	log.Infof("avg response time: %s", sender.getAvgRequestDuration().String())
	avgReqsPerSec := float64(len(identities)*numberOfRequestsPerID) / duration.Seconds()
	log.Infof("avg total throughput: %7.3f requests/second", avgReqsPerSec)
	avgReqsPerSecSuccess := float64(sender.statusCounter["200 OK"]) / duration.Seconds()
	log.Infof("avg successful throughput: %7.3f requests/second", avgReqsPerSecSuccess)
}
