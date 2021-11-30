package profiling

import (
	"os"
	"runtime"
	"runtime/pprof"

	log "github.com/sirupsen/logrus"
)

func RecordBlockProfile(filename string) *os.File {
	log.Warnf("blocking profiling enabled, this will affect performance, file: %s", filename)

	f, err := os.Create(filename)
	if err != nil {
		log.Errorf("could not create blocking profile file: %v", err)
	}

	runtime.SetBlockProfileRate(1)

	return f
}

func StopBlockProfileRecording(file *os.File) {
	log.Infof("writing blocking profile data to file: %s", file.Name())

	if err := pprof.Lookup("block").WriteTo(file, 0); err != nil {
		log.Errorf("could not write blocking profile: %v", err)
		return
	}

	if err := file.Close(); err != nil {
		log.Errorf("error when closing blocking profile file: %v", err)
	}
}
