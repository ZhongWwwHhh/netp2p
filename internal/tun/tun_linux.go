//go:build linux

package tun

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const tunDevicePath = "/dev/net/tun"

// openDevice attaches to a TUN interface. IFF_NO_PI is essential: without it the
// kernel prefixes every packet with a 4-byte flag/protocol header that the
// overlay does not expect.
func openDevice(name string) (io.ReadWriteCloser, string, error) {
	if name == "" {
		name = "netp2p0"
	}
	fd, err := unix.Open(tunDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", tunDevicePath, err)
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("invalid tun name %q: %w", name, err)
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("TUNSETIFF on %q (needs CAP_NET_ADMIN): %w", name, err)
	}
	// The kernel rewrites the name when the requested one is already in use.
	return os.NewFile(uintptr(fd), tunDevicePath), request.Name(), nil
}
