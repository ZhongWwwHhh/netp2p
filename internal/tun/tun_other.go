//go:build !linux

package tun

import (
	"fmt"
	"io"
	"runtime"
)

func openDevice(name string) (io.ReadWriteCloser, string, error) {
	return nil, "", fmt.Errorf("%w: tun is implemented for Linux only, not %s", ErrUnsupported, runtime.GOOS)
}
