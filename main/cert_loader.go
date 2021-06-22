package main

import "time"

var (
	certLoadInterval     time.Duration
	maxCertLoadFailCount int
)

func setInterval(reloadEveryMinute bool) {
	if reloadEveryMinute {
		certLoadInterval = time.Minute
		maxCertLoadFailCount = 60
	} else {
		certLoadInterval = time.Hour
		maxCertLoadFailCount = 3
	}
}

func startLoadScheduler(load func(), reloadEveryMinute bool) {
	setInterval(reloadEveryMinute)

	load()
	for range time.Tick(certLoadInterval) {
		load()
	}
}
