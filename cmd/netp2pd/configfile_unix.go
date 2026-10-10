//go:build !windows

package main

import "os"

func secureRuntimeConfig(path string) error {
	return os.Chmod(path, 0o600)
}
