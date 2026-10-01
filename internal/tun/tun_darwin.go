//go:build darwin

package tun

import (
	"fmt"
	"io"
	"os"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// openDevice attaches to a utun interface through wireguard-go's TUN backend.
// It requires root, and the resulting interface name (utunN) may differ from
// the requested one.
func openDevice(name string) (io.ReadWriteCloser, string, error) {
	if name == "" {
		name = "netp2p0"
	}
	device, err := wgtun.CreateTUN(name, DefaultMTU)
	if err != nil {
		return nil, "", fmt.Errorf("create utun device %q (needs root): %w", name, err)
	}
	actual, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, "", err
	}
	file := device.File()
	if file == nil {
		_ = device.Close()
		return nil, "", fmt.Errorf("utun device %q has no file handle", actual)
	}
	return &wireguardFile{file: file, device: device}, actual, nil
}

// wireguardFile adapts a wireguard-go TUN device to io.ReadWriteCloser. Closing
// the device also releases its file descriptor and event goroutine.
type wireguardFile struct {
	file   *os.File
	device wgtun.Device
}

func (adapter *wireguardFile) Read(p []byte) (int, error)  { return adapter.file.Read(p) }
func (adapter *wireguardFile) Write(p []byte) (int, error) { return adapter.file.Write(p) }
func (adapter *wireguardFile) Close() error                { return adapter.device.Close() }
