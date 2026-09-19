package client

import (
	"log"
	"os"
)

// debugDataPlane enables verbose data-plane tracing when NETP2P_DEBUG_DATA is
// set. Silent by default so the packet path stays quiet in normal operation.
var debugDataPlane = os.Getenv("NETP2P_DEBUG_DATA") != ""

func debugDrop(format string, args ...any) {
	if !debugDataPlane {
		return
	}
	log.Printf("[data] "+format, args...)
}
