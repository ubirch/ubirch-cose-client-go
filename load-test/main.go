package main

import (
	"flag"
	"fmt"
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
)

func main() {
	c := Config{}
	err := c.load()
	if err != nil {
		log.Fatalf("could not load configuration: %v", err)
	}

	sender := NewSender()

	identities, err := c.initTestIdentities(sender)
	if err != nil {
		log.Fatalf("could not initialize identities: %v", err)
	}

	log.Infof("%d identities, %d requests each => sending [ %d ] requests", len(identities), numberOfRequestsPerID, len(identities)*numberOfRequestsPerID)
	log.Infof("%3d requests per second per identity", requestsPerSecondPerID)
	log.Infof("%3d requests per second overall", len(identities)*requestsPerSecondPerID)

	wg := &sync.WaitGroup{}
	start := time.Now()

	i := 0
	n := len(identities)
	for uid, auth := range identities {
		offset := time.Duration((i*1000)/n) * time.Millisecond
		i += 1

		wg.Add(1)
		go sender.sendRequests(*c.url, uid, auth, offset, wg)
	}

	wg.Wait()
	duration := time.Since(start)
	log.Infof("[ %6d ] requests done after [ %7.3f ] seconds ", len(identities)*numberOfRequestsPerID, duration.Seconds())

	for status, count := range sender.statusCounter {
		log.Infof("[ %6d ] x %s", count, status)
	}

	log.Infof("avg response time: %s", sender.getAvgRequestDuration().String())
	avgReqsPerSec := float64(len(identities)*numberOfRequestsPerID) / duration.Seconds()
	log.Infof("avg total throughput: %7.3f requests/second", avgReqsPerSec)
	avgReqsPerSecSuccess := float64(sender.statusCounter["200 OK"]) / duration.Seconds()
	log.Infof("avg successful throughput: %7.3f requests/second", avgReqsPerSecSuccess)
	fmt.Print("\n\n========================================================================================================================\n\n")
}
