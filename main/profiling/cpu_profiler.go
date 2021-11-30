package profiling

import (
	"os"
	"runtime/pprof"

	log "github.com/sirupsen/logrus"
)

func RecordCPUProfile(filename string) *os.File {
	log.Infof("enabling CPU profiling to file: %s", filename)

	f, err := os.Create(filename)
	if err != nil {
		log.Errorf("could not create CPU profile file: %s", err)
	}

	if err := pprof.StartCPUProfile(f); err != nil {
		log.Errorf("could not start CPU profile: %s", err)
	}

	return f
}

func StopCPUProfileRecording(file *os.File) {
	log.Infof("writing CPU profile data to file: %s", file.Name())

	pprof.StopCPUProfile()

	if err := file.Close(); err != nil {
		log.Errorf("error when closing CPU profile file: %v", err)
	}
}
