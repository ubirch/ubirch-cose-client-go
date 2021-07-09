package main

import (
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	numberOfTestIDs        = 1
	numberOfRequestsPerID  = 1
	requestsPerSecondPerID = 1
)

var configFile = "config.json"

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})

	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	c := Config{}
	err := c.Load(configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	identities := c.getTestIdentities()
	sender := NewSender()

	//for id, auth := range identities {
	//	err := sender.register(c.Url, id, auth, c.RegisterAuth)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//}

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
	log.Infof(" = = = => [ %4d ] requests done after [ %7.3f ] seconds <= = = = ", len(identities)*numberOfRequestsPerID, time.Since(start).Seconds())

	for status, count := range sender.statusCounter {
		log.Infof("[ %4d ] x %s", count, status)
	}
}
