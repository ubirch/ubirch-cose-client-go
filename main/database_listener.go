package main

import (
	"time"

	"github.com/lib/pq"

	log "github.com/sirupsen/logrus"
)

func initListener(dsn, channelName string) (*pq.Listener, error) {
	minReconn := 15 * time.Second
	maxReconn := 2 * time.Minute

	l := pq.NewListener(dsn, minReconn, maxReconn, reportEvent)

	err := l.Listen(channelName)
	if err != nil {
		l.Close()
		return nil, err
	}

	return l, nil
}

func waitForNotification(l *pq.Listener, doWhenNotified func()) {
	for {
		select {
		case <-l.Notify:
			doWhenNotified()
		case <-time.After(15 * time.Minute):
			go func() {
				err := l.Ping()
				if err != nil {
					log.Errorf("pq.Listener.Ping() returned error: %v", err)
				}
			}()
		}
	}
}

func reportEvent(ev pq.ListenerEventType, err error) {
	var event string

	switch ev {
	case pq.ListenerEventConnected:
		event = "connected"
	case pq.ListenerEventDisconnected:
		event = "disconnected"
	case pq.ListenerEventReconnected:
		event = "reconnected"
	case pq.ListenerEventConnectionAttemptFailed:
		event = "connection attempt failed"
	}
	log.Debugf("database listener event: %s", event)

	if err != nil {
		log.Errorf("database listener error: %v", err)
	}
}
