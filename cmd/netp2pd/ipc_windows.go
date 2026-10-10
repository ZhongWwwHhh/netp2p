//go:build windows

package main

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

// Interactive users only need to open and exchange IPC requests. Full access
// remains limited to SYSTEM and Administrators.
const ipcPipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

func listenIPC(path string) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("IPC path is empty")
	}
	return winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: ipcPipeSDDL,
		InputBufferSize:    4096,
		OutputBufferSize:   4096,
	})
}
