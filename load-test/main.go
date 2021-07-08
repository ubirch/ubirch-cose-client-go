package main

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	clientBaseURL          = "http://localhost:8080/"
	configFile             = "config.json"
	numberOfTestIDs        = 1
	numberOfRequestsPerID  = 1
	requestsPerSecondPerID = 1
)

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})

	c := Config{}
	err := c.Load(configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	identities := getTestIdentities(c)

	wg := &sync.WaitGroup{}
	sender := NewSender()

	//for id, auth := range identities {
	//	err := sender.register(id, auth, registerAuth)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//}

	log.Infof("%d identities, %d requests each => sending [ %d ] requests", len(identities), numberOfRequestsPerID, len(identities)*numberOfRequestsPerID)
	log.Infof("%3d requests per second per identity", requestsPerSecondPerID)
	log.Infof("%3d requests per second overall", len(identities)*requestsPerSecondPerID)

	start := time.Now()

	for uid, auth := range identities {
		wg.Add(1)
		go sender.sendRequests(uid, auth, wg)
	}

	wg.Wait()
	log.Infof(" = = = => requests done after [ %7.3f ] seconds <= = = = ", time.Since(start).Seconds())
}
