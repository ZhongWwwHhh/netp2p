//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

func listenIPC(path string) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("IPC path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create IPC directory: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("restrict IPC socket: %w", err)
	}
	return listener, nil
}
